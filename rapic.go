package rapic

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

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

type AuthScheme string

const (
	AUTH_URL    AuthScheme = "URL"
	AUTH_BASIC  AuthScheme = "Basic"
	AUTH_BEARER AuthScheme = "Bearer"
	AUTH_DIGEST AuthScheme = "Digest"
	AUTH_CUSTOM AuthScheme = "Custom"
)

type DigestAlgo string

const (
	DIGEST_MD5       DigestAlgo = "md5"
	DIGEST_SHA256    DigestAlgo = "sha-256"
	DIGEST_SHA512    DigestAlgo = "sha-512"
	DIGEST_SHA512256 DigestAlgo = "sha-512-256"

	DIGEST_MD5_SESS       DigestAlgo = "md5-sess"
	DIGEST_SHA256_SESS    DigestAlgo = "sha-256-sess"
	DIGEST_SHA512_SESS    DigestAlgo = "sha-512-sess"
	DIGEST_SHA512256_SESS DigestAlgo = "sha-512-256-sess"
)

type CookieJar struct {
	http.CookieJar
}

type Cookie struct {
	Name   string
	Value  string
	Path   string
	Domain string
}

type Authorization struct {
	Scheme AuthScheme

	Username string
	Password string

	// Only for Bearer auth
	Token string

	// Only for Digest auth.
	Digest AuthDigest

	// The value for Custom auth
	Value string
}

type AuthDigest struct {
	// The default algorithm used is DIGEST_SHA256
	Algorithm DigestAlgo

	Realm       string
	Nonce       string
	QOP         string
	NonceCount  string
	ClientNonce string
	Opaque      string
}

type Client struct {
	Settings Settings

	Scheme   string
	Endpoint string

	Path  string
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

type Response struct {
}

func reqIsSuccess(code int) bool {
	if code >= 200 && code < 400 {
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

func cookieKeyValue(pair string) (key, value string) {
	split := strings.Split(pair, "=")

	if len(split) < 2 {
		return
	}

	key = split[0]
	value = strings.Join(split[1:], "=")

	return
}

func cookieExpires(e string) (t time.Time, err error) {
	if t, err = time.Parse(time.RFC1123, e); err == nil {
		return
	} else if t, err = time.Parse(time.RFC1123Z, e); err == nil {
		return
	} else if t, err = time.Parse(time.RFC850, e); err == nil {
		return
	} else if t, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", e); err == nil {
		return
	}

	return
}

func cookieParse(cookies []string) (c []*http.Cookie) {
	for _, cookie := range cookies {
		if cookie == "" {
			continue
		}

		new := new(http.Cookie)
		for id, chip := range strings.Split(cookie, "; ") {
			if strings.ContainsRune(chip, '=') {
				key, value := cookieKeyValue(chip)

				switch strings.ToLower(key) {
				case "path":
					new.Path = value
				case "samesite":
					if strings.ToLower(value) == "lax" {
						new.SameSite = http.SameSiteLaxMode

					} else if strings.ToLower(value) == "none" {
						new.SameSite = http.SameSiteNoneMode

					} else if strings.ToLower(value) == "strict" {
						new.SameSite = http.SameSiteStrictMode
					} else {
						new.SameSite = http.SameSiteDefaultMode
					}
				case "max-age":
					new.MaxAge, _ = strconv.Atoi(value)
				case "expires":
					new.Expires, _ = cookieExpires(value)
					new.RawExpires = value
				case "domain":
					new.Domain = value
				default:
					if id == 0 {
						new.Name = key
						new.Value = value
					} else {
						new.Unparsed = append(new.Unparsed, chip)
					}
				}
			} else {
				switch strings.ToLower(chip) {
				case "httponly":
					new.HttpOnly = true
				case "secure":
					new.Secure = true
				default:
					new.Unparsed = append(new.Unparsed, chip)
				}
			}
		}

		c = append(c, new)
	}

	return
}

// New return an initialized Client struct.
// This is the main client, you can make request from it
// or create children for new request with their inheritance
//
// This function require a Endpoint URL with scheme Path.
// You can also specify a Auth with the optinal Authorization arg
func New(endpoint string, auth ...Authorization) (main Client, err error) {
	URL, err := url.Parse(endpoint)
	if err != nil {
		return
	}

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

	main.Scheme = URL.Scheme
	URL.Scheme = ""
	main.Endpoint = pathFormatting(URL.String())

	main.Query = make(url.Values)
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
		child.Path = child.Path + pathFormatting(path[0])
	}

	return
}

// AddCookie adds the key, value pair to the cookie Jar.
// It does nothing if the URL's scheme is not HTTP or HTTPS.
func (j *CookieJar) Add(URL string, new ...*http.Cookie) error {
	u, err := url.Parse(URL)
	if err != nil {
		return err
	}

	old := j.CookieJar.Cookies(u)
	new = append(new, old...)

	http.CookieJar(*j).SetCookies(u, new)

	return nil
}

// Set the cookie entries associated with the given key to the element value.
// It replaces any existing values associated with the given key in Jar.
// It does nothing if the URL's scheme is not HTTP or HTTPS.
func (j *CookieJar) Set(URL string, c *http.Cookie) error {
	u, err := url.Parse(URL)
	if err != nil {
		return err
	}

	jar := j.CookieJar.Cookies(u)
	for k := range jar {
		if jar[k].Name == c.Name {
			jar[k] = c
		}
	}

	http.CookieJar(*j).SetCookies(u, jar)

	return nil
}

// Del deletes all cookie entries associated with the given key name in Jar.
// It does nothing if the URL's scheme is not HTTP or HTTPS.
func (j *CookieJar) Del(URL string, name string) error {
	u, err := url.Parse(URL)
	if err != nil {
		return err
	}

	jar := j.CookieJar.Cookies(u)
	for k := range jar {
		if jar[k].Name == name {
			jar[k].Expires = time.Unix(0, 0)
		}
	}

	http.CookieJar(*j).SetCookies(u, jar)

	return nil
}

// Get the first cookie associated with the given key.
// If there are no values associated with the key, Get returns a empty http.Cookie
// It does nothing if the URL's scheme is not HTTP or HTTPS.
func (j *CookieJar) Get(URL string, name string) (*http.Cookie, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}

	jar := j.CookieJar.Cookies(u)

	for k := range jar {
		if jar[k].Name == name {
			return jar[k], nil
		}
	}

	return &http.Cookie{}, nil
}

// Clear deletes ALL cookie entries in Jar.
func (j *CookieJar) Clear() (err error) {
	j.CookieJar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

	return
}

// TODO
func (d *AuthDigest) Build(user, password, path string, body *string, method RequestMethods) (digest string) {
	var HA1, HA2, response string

	if path == "" {
		path = "/"
	}

	HA1 = d.Hash(user + ":" + d.Realm + ":" + password)

	if strings.HasSuffix(string(d.Algorithm), "sess") {
		HA1 = d.Hash(HA1 + ":" + d.Nonce + ":" + d.NonceCount)
	}

	if strings.Contains(d.QOP, "auth-int") {
		HA2 = d.Hash(string(method) + ":" + path + ":" + d.Hash(*body))
	} else {
		HA2 = d.Hash(string(method) + ":" + path)
	}

	if strings.Contains(d.QOP, "auth") || strings.Contains(d.QOP, "auth-int") {
		response = d.Hash(HA1 + ":" + d.Nonce + ":" + d.NonceCount + ":" + d.ClientNonce + ":" + d.QOP + ":" + HA2)
	} else {
		response = d.Hash(HA1 + ":" + d.Nonce + ":" + HA2)
	}

	_ = response

	digest = `username="` + user + `"`
	digest = digest + `, uri="` + path + `"`
	digest = digest + `, algorithm="` + string(d.Algorithm) + `"`
	digest = digest + `, response="` + response + `"`

	if d.Realm != "" {
		digest = digest + `, realm="` + d.Realm + `"`
	}

	if d.Nonce != "" {
		digest = digest + `, nonce="` + d.Nonce + `"`
	}

	if d.Opaque != "" {
		digest = digest + `, opaque="` + d.Opaque + `"`
	}

	return
}

// TODO
func (d *AuthDigest) Hash(s string) (hashed string) {
	switch d.Algorithm {
	case DIGEST_MD5, DIGEST_MD5_SESS:
		hashed = fmt.Sprintf("%x", md5.Sum([]byte(s)))
	case DIGEST_SHA256, DIGEST_SHA256_SESS:
		hashed = fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
	case DIGEST_SHA512, DIGEST_SHA512_SESS:
		hashed = fmt.Sprintf("%x", sha512.Sum512([]byte(s)))
	case DIGEST_SHA512256, DIGEST_SHA512256_SESS:
		hashed = fmt.Sprintf("%x", sha512.Sum512_256([]byte(s)))
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

// URI constructs the URI of the target request
func (c *Client) URI() (uri string) {
	// Scheme
	uri = c.Scheme + "://"

	// Authority userinfo
	if c.Authorization.Scheme == AUTH_URL {
		uri = uri +
			url.QueryEscape(c.Authorization.Username) + `:` +
			url.QueryEscape(c.Authorization.Password) + `@`
	}

	// Authority + Path
	uri = uri + c.Endpoint + c.Path

	// Query
	if len(c.Query) > 0 {
		uri = uri + `?` + c.Query.Encode()
	}

	return
}

// TODO
func (c *Client) Request(method RequestMethods, uri string, body *string, resp *Response) (res *http.Response, err error) {
	req := &http.Request{}

	if body == nil {
		if req, err = http.NewRequest(string(method), uri, nil); err != nil {
			return
		}
	} else {
		if req, err = http.NewRequest(string(method), uri, strings.NewReader(*body)); err != nil {
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
			c.Header.Set("Authorization", "Digest "+c.Authorization.Digest.Build(
				c.Authorization.Username,
				c.Authorization.Password,
				c.Path,
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

				if req.URL.Host != c.Endpoint && !c.Settings.FollowAuth {
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
			c.Cookie.Add(uri, cookieParse(res.Header.Values("Set-Cookie"))...)
		}
	}

	return
}
