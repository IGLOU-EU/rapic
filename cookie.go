package rapic

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
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
