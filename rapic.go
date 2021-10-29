package rapic

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

type RequestMethods string

const (
	METHOD_CONNECT RequestMethods = "CONNECT"
	METHOD_DELETE  RequestMethods = "DELETE"
	METHOD_GET     RequestMethods = "GET"
	METHOD_HEAD    RequestMethods = "HEAD"
	METHOD_OPTIONS RequestMethods = "OPTIONS"
	METHOD_PATCH   RequestMethods = "PATCH"
	METHOD_POST    RequestMethods = "POST"
	METHOD_PUT     RequestMethods = "PUT"
	METHOD_TRACE   RequestMethods = "TRACE"
)

type Client struct {
	Settings Settings

	URL   *url.URL
	Query url.Values

	Header http.Header
	Cookie CookieJar

	Authorization Authorization
}

type Settings struct {
	// Follow is for auto follow the HTTP 3xx as redirects (def: true)
	Follow bool
	// FollowAuth Keep authorization header when redirect to a different host (def: false)
	FollowAuth bool
	// FollowReferer keep the referer header when a redirect happens (def: true)
	FollowReferer bool
	// MaxRedirect to set the maximum number of redirects to follow (def: 2)
	MaxRedirect uint8
	// AutoCookie store automatically cookie's if a set-cookie is found in header (def: true)
	AutoCookie bool
	// Retry if request is not 2xx or 3xx (def: true)
	Retry bool
	// MaxRetry to set the maximum number of retry (def: 1)
	MaxRetry uint8
	// WaitRetry to set the time to wait before retry in second (def: 10)
	WaitRetry time.Duration
}

// TODO
type Response struct {
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// reqIsSuccess checks whether a request is successful.
// a request is successful when the http code is >= 100 or < 400
// with an exception at 401, in accordance with Digest Auth RFC7616-3.3.
func reqIsSuccess(code int) bool {
	if (code >= 100 && code < 400) || code == 401 {
		return true
	}

	return false
}

func pathFormatting(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	} else if strings.HasPrefix(p, "//") {
		p = strings.TrimPrefix(p, "/")
	}

	return strings.TrimSuffix(p, "/")
}

// New return an initialized Client struct.
// This is the main client, you can make request from it
// or create children for new request with their inheritance
//
// This function require a Endpoint URL with scheme Path.
// You can also specify a Auth with the optinal Authorization arg
func New(endpoint string, auth ...Authorization) (main Client, err error) {

	main.Settings = Settings{
		Follow:        true,
		FollowAuth:    false,
		FollowReferer: true,
		MaxRedirect:   2,
		AutoCookie:    true,
		Retry:         true,
		MaxRetry:      1,
		WaitRetry:     10,
	}

	if main.URL, err = url.Parse(endpoint); err != nil {
		return
	}

	if main.Query, err = url.ParseQuery(main.URL.RawQuery); err != nil {
		return
	}

	main.Header = make(http.Header)
	main.Authorization.Digest.Algorithm = DIGEST_SHA256

	if len(auth) > 0 {
		main.Authorization = auth[0]
	}

	main.Cookie.CookieJar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

	return
}

// NewChild create a children client with parent inheritance.
// This new client are isolated from the parent.
//
// Can take a relative path from parent
func (parent *Client) NewChild(path ...string) (child Client) {
	child = *parent

	if len(path) > 0 {
		child.URL.Path = child.URL.Path + pathFormatting(path[0])
	}

	return
}

// FlushHeader remove all stored header
func (c *Client) FlushHeader() {
	c.Header = http.Header{}
}

// FlushQuery remove all stored query
func (c *Client) FlushQuery() {
	c.Query = url.Values{}
}

// TODO
func (c *Client) Request(method RequestMethods, body *string, res *http.Response) (err error) {
	req := &http.Request{}

	c.URL.RawQuery = c.Query.Encode()

	if body == nil {
		if req, err = http.NewRequest(string(method), c.URL.String(), nil); err != nil {
			return
		}
	} else {
		if req, err = http.NewRequest(string(method), c.URL.String(), strings.NewReader(*body)); err != nil {
			return
		}
	}

	// Auth
	if c.Authorization.Scheme != "" {
		switch c.Authorization.Scheme {
		case AUTH_BASIC:
			req.SetBasicAuth(c.Authorization.Username, c.Authorization.Password)
		case AUTH_BEARER:
			c.Header.Set("Authorization", "Bearer "+c.Authorization.Token)
		case AUTH_DIGEST:
			if c.Authorization.Digest.URI != "*" {
				c.Authorization.Digest.URI = c.URL.Path
			}
			if c.Authorization.Digest.Opaque == "" {
				c.Authorization.Digest.Opaque = c.URL.Opaque
			}
			c.Header.Set("Authorization", "Digest "+c.Authorization.Digest.Build(
				c.Authorization.Username,
				c.Authorization.Password,
				body,
				method,
			))
		case AUTH_CUSTOM:
			c.Header.Set("Authorization", c.Authorization.Value)
		default:
			err = errors.New("unknow Authorization Scheme")
			return
		}
	}

	// Header
	req.Header = c.Header

	// Request
	for i := uint8(0); ; i++ {
		cli := &http.Client{
			Jar: c.Cookie,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if !c.Settings.Follow {
					return http.ErrUseLastResponse
				}

				if !c.Settings.FollowReferer {
					req.Header.Del("Referer")
				}

				if req.URL.Host != c.URL.Host && !c.Settings.FollowAuth {
					req.Header.Del("Authorization")
				}

				nb := len(via)
				if nb <= int(c.Settings.MaxRedirect) {
					return errors.New("stopped after " + strconv.Itoa(nb) + " redirects")
				}

				return nil
			},
		}

		res, err = cli.Do(req)

		if (err == nil && reqIsSuccess(res.StatusCode)) || c.Settings.MaxRetry <= i {
			break
		}

		if c.Settings.WaitRetry > 0 {
			time.Sleep(c.Settings.WaitRetry * time.Second)
		}
	}

	if c.Settings.AutoCookie {
		if err == nil {
			c.Cookie.Add(c.URL.String(), cookieParse(res.Header.Values("Set-Cookie"))...)
		}
	}

	return
}
