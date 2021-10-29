package rapic

import (
	"bytes"
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

type AuthScheme string

const (
	AUTH_BASIC  AuthScheme = "Basic"
	AUTH_BEARER AuthScheme = "Bearer"
	AUTH_DIGEST AuthScheme = "Digest"
	AUTH_CUSTOM AuthScheme = "Custom"
)

// DigestAlgo is Hash Algorithms for HTTP Digest Authentication
// But add SHA512 support to be futureproof
// Defined under RFC7616-6.1 at https://datatracker.ietf.org/doc/html/rfc7616#section-6.1
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

// AuthDigest is the available Authorization Digest Setting Field
// Defined under RFC7616-3.4 at https://datatracker.ietf.org/doc/html/rfc7616#section-3.4
type AuthDigest struct {
	// The default algorithm used is DIGEST_SHA256
	Algorithm DigestAlgo

	Realm    string
	URI      string
	QOP      string
	Nonce    string
	CNonce   string
	NC       string
	UserHash bool
	Opaque   string
}

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

// Build is the Digest Access Authentication builder
// Generate a valid Digest header value in accordance with the RFC7616
// But retains backwards compatibility with the RFC2069
//
// Suppose you have filled the information in AuthDigest{}
func (d *AuthDigest) Build(user, password string, body *string, method RequestMethods) string {
	var buffer bytes.Buffer
	var A1, A2, digest string

	// Defined under RFC7616-3.4.2 at https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.2
	A1 = user + ":" + d.Realm + ":" + password
	if strings.HasSuffix(string(d.Algorithm), "sess") {
		A1 = d.Hash(A1) + ":" + d.Nonce + ":" + d.CNonce
	}

	// Defined under RFC7616-3.4.3 at https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.3
	if d.QOP == "auth-int" {
		A2 = string(method) + ":" + d.URI + ":" + d.Hash(*body)
	} else {
		A2 = string(method) + ":" + d.URI
	}

	// Defined under RFC7616-3.4.1 at https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.2
	// But not folow the deprecated backward compatibility with RFC2069-2.1.2
	if d.QOP == "auth" || d.QOP == "auth-int" {
		digest = d.Hash(d.Hash(A1) + ":" + d.Nonce + ":" + d.NC + ":" + d.CNonce + ":" + d.QOP + ":" + d.Hash(A2))
	} else {
		digest = d.Hash(d.Hash(A1) + ":" + d.Nonce + ":" + d.Hash(A2))
	}

	// fmt.Println(buffer.String())
	// Formating the Authorization Header Field
	// Defined under RFC7616-3.4 at https://datatracker.ietf.org/doc/html/rfc7616#section-3.4
	buffer.WriteString(`uri="` + d.URI + `"`)
	buffer.WriteString(`, algorithm=` + string(d.Algorithm))
	buffer.WriteString(`, response="` + digest + `"`)

	// User hash or UTF-8 username declaration header
	// Defined under RFC7616-3.4.4 at https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.4
	// And under RFC7616-4 at https://datatracker.ietf.org/doc/html/rfc7616#section-4
	if d.UserHash {
		buffer.WriteString(`, username="` + d.Hash(user) + `"`)
	} else if isASCII(user) {
		buffer.WriteString(`, username="` + user + `"`)
	} else {
		buffer.WriteString(`, username*=UTF-8''` + url.QueryEscape(user))
	}

	if d.UserHash {
		buffer.WriteString(`, userhash=true`)
	} else {
		buffer.WriteString(`, userhash=false`)
	}

	if d.Realm != "" {
		buffer.WriteString(`, realm="` + d.Realm + `"`)
	}

	if d.Nonce != "" {
		buffer.WriteString(`, nonce="` + d.Nonce + `"`)
	}

	if d.NC != "" {
		buffer.WriteString(`, nc=` + d.NC)
	}

	if d.CNonce != "" {
		buffer.WriteString(`, cnonce="` + d.CNonce + `"`)
	}

	if d.QOP != "" {
		buffer.WriteString(`, qop=` + d.QOP)
	}

	if d.Opaque != "" {
		buffer.WriteString(`, opaque="` + d.Opaque + `"`)
	}

	return buffer.String()
}

// Hash is the hashing function for Digest Access Authentication
// AuthDigest can be used with Algorithm
// - MD5 (RFC2069 and RFC2617)
// - SHA-256 (RFC7616)
// - SHA-512-256 (RFC7616)
// - SHA-512 (for futureproof)
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
