package rapic

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	METHOD_CONNECT = "CONNECT"
	METHOD_DELETE  = "DELETE"
	METHOD_GET     = "GET"
	METHOD_HEAD    = "HEAD"
	METHOD_OPTIONS = "OPTIONS"
	METHOD_PATCH   = "PATCH"
	METHOD_POST    = "POST"
	METHOD_PUT     = "PUT"
	METHOD_TRACE   = "TRACE"
)

type Response struct {
	StatusCode int
	Status     string

	Header http.Header
	Body   []byte
}

type Client struct {
	Method string

	Scheme   string
	Endpoint string
	Path     string
	Query    url.Values

	Header      http.Header
	Cookie      []http.Cookie
	ContentType ContentType
	BasicAuth   BasicAuth

	Body *bytes.Reader
}

type ContentType struct {
	MediaType string
	Charset   string
}

type BasicAuth struct {
	username string
	password string
}

// Cookie
func (c *Client) AddCookie(new ...http.Cookie) *Client {
	c.Cookie = append(c.Cookie, new...)

	return c
}

func (c *Client) UpdateCookie(ck http.Cookie) *Client {
	for k, v := range c.Cookie {
		if ck.Name == v.Name {
			c.Cookie[k] = ck
			return c
		}
	}

	return c
}

func (c *Client) RemoveCookie(name string) *Client {
	for k, v := range c.Cookie {
		if name == v.Name {
			c.Cookie = append(c.Cookie[:k], c.Cookie[k+1:]...)
			return c
		}
	}

	return c
}

func (c *Client) GetCookie(name string) http.Cookie {
	for k, v := range c.Cookie {
		if name == v.Name {
			return c.Cookie[k]
		}
	}

	return http.Cookie{}
}

// Header
func (c *Client) isNilHeader() {
	if c.Header == nil {
		c.Header = make(http.Header)
	}
}

func (c *Client) AddHeader(new http.Header) *Client {
	c.isNilHeader()

	for n, v := range new {
		// c.Header[n] = v
		c.Header.Add(n, strings.Join(v, ", "))
	}

	return c
}

func (c *Client) SetHeader(name string, value string) *Client {
	c.isNilHeader()

	c.Header[name] = []string{value}

	return c
}

func (c *Client) RemoveHeader(key ...string) *Client {
	for _, v := range key {
		delete(c.Header, v)
	}

	return c
}

func (c *Client) GetHeader(key string) string {
	if _, ok := c.Header[key]; ok {
		return key + ": " + strings.Join(c.Header[key], ",")
	}

	return ""
}

func (c *Client) FlushHeader() *Client {
	c.Header = http.Header{}

	return c
}

// Request

func (c Client) GetURL() string {
	return c.Endpoint + c.Path
}

func (c Client) GetURI() string {
	var uri string

	if c.Scheme != "" {
		uri = c.Scheme + ":"
	}

	if c.Endpoint == "" {
		uri = uri + c.Path
	} else {
		uri = uri + "//" + c.Endpoint + c.Path
	}

	return uri
}

func (c Client) GetContentType() string {
	ct := c.ContentType.MediaType

	if c.ContentType.Charset != "" {
		ct = ct + "; charset=" + c.ContentType.Charset
	}

	return ct
}

func (c *Client) Request() (*Response, error) {
	var err error

	req := &http.Request{}
	cli := &http.Client{}
	res := &http.Response{}
	out := &Response{}

	if c.Body == nil {
		if req, err = http.NewRequest(c.Method, c.GetURI(), nil); err != nil {
			return out, err
		}
	} else {
		if req, err = http.NewRequest(c.Method, c.GetURI(), c.Body); err != nil {
			return out, err
		}
	}

	if c.BasicAuth != (BasicAuth{}) {
		req.SetBasicAuth(c.BasicAuth.username, c.BasicAuth.password)
	}

	for _, cookie := range c.Cookie {
		req.AddCookie(&cookie)
	}

	req.Header = c.Header

	res, err = cli.Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()

	out.Body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return out, err
	}

	out.StatusCode = res.StatusCode
	out.Status = res.Status
	out.Header = res.Header

	return out, nil
}
