package rapic_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/IGLOU-EU/rapic"
)

func tError(r bool, s string, t *testing.T) {
	if r {
		t.Errorf("%s", s)
		t.Fail()
	}
}

func TestCookie(t *testing.T) {
	var client rapic.Client

	ck := []http.Cookie{
		{},
		{
			Name: "qwerty",
		},
		{
			Name:  "poiuytr",
			Value: "mnbvc",
		},
		{},
		{
			Name:  "Cookie",
			Value: "Lover",
		},
	}

	client.AddCookie(ck...)
	tError(len(client.Cookie) != len(ck), fmt.Sprintf("Bad number of cookies\nExpect: %d, Give: %d\n%#v\n", len(ck), len(client.Cookie), client.Cookie), t)

	ck[1].Value = "azerty"
	ck[4].Value = "Hater"

	ck = append(ck, http.Cookie{Name: "NotExist"})

	for _, v := range ck {
		client.UpdateCookie(v)
		tError(client.GetCookie(v.Name).Value != v.Value, fmt.Sprintf("Bad cookies value\nExpect: %s, Give: %s\n", v.Value, client.GetCookie(v.Name).Value), t)
	}

	for _, v := range ck {
		client.RemoveCookie(v.Name)
	}

	tError(len(client.Cookie) != 0, fmt.Sprintf("Oups cookies is not empty\n%#v\n", client.Cookie), t)
}

func TestHeader(t *testing.T) {
	var client rapic.Client

	h := http.Header{
		"azerty":  []string{"qwerty"},
		"qwerty":  []string{"azerty"},
		"Cookies": []string{"Lover"},
		"Cocoa":   []string{""},
		"":        []string{"Empty to me !"},
	}

	client.AddHeader(h)
	tError(len(client.Header) != len(h), fmt.Sprintf("Bad number of Header\nExpect: %d, Give: %d\n%#v\n", len(h), len(client.Header), client.Header), t)

	for n, v := range h {
		client.SetHeader(n, v[0])
		tError(client.GetHeader(n) == "", fmt.Sprintf("Bad header set\nExpect: %s: %#v not exist on Header map\n", n, v), t)
	}

	tError(client.GetHeader("NotExist!") != "", fmt.Sprintf("Unknow Header expect to return an empty string\n%#v\n", client.Header), t)

	for n, v := range h {
		client.RemoveHeader(n)
		tError(client.GetHeader(n) != "", fmt.Sprintf("Can't remove herder key\nKey: %s, Value: %s\n%#v\n", n, v, client.Header), t)
	}

	client.AddHeader(h)
	client.FlushHeader()
	tError(len(client.Header) != 0, fmt.Sprintf("Header not flushed\nExpect len 0, Give: %d\n%#v\n", len(client.Header), client.Header), t)
}

func TestTool(t *testing.T) {
	var client rapic.Client

	u := []struct {
		url  string
		path string
		res  string
	}{
		{},
		{
			url: "www.openbsd.org",
			res: "www.openbsd.org",
		},
		{
			url:  "www.openbsd.org",
			path: "/goals.html",
			res:  "www.openbsd.org/goals.html",
		},
		{
			url:  "",
			path: "/HoNoMyEndpoint.Is404",
			res:  "/HoNoMyEndpoint.Is404",
		},
	}

	for _, v := range u {
		client.Endpoint = v.url
		client.Path = v.path

		r := client.GetURL()

		tError(r != v.res, fmt.Sprintf("Oups, bad URL reply\nExpect: %s, Give: %s\n%#v\n", v.res, r, client), t)
	}

	i := []struct {
		url    string
		path   string
		scheme string
		res    string
	}{
		{},
		{
			scheme: "https",
			url:    "www.openbsd.org",
			res:    "https://www.openbsd.org",
		},
		{
			scheme: "https",
			url:    "www.openbsd.org",
			path:   "/goals.html",
			res:    "https://www.openbsd.org/goals.html",
		},
		{
			url:  "",
			path: "/HoNoMyEndpoint.Is404",
			res:  "/HoNoMyEndpoint.Is404",
		},
	}

	for _, v := range i {
		client.Endpoint = v.url
		client.Path = v.path
		client.Scheme = v.scheme

		r := client.GetURI()

		tError(r != v.res, fmt.Sprintf("Oups, bad URI reply\nExpect: %s, Give: %s\n%#v\n", v.res, r, client), t)
	}

	c := []struct {
		char  string
		media string
		res   string
	}{
		{},
		{
			char:  "utf-8",
			media: "text/fragment+html",
			res:   "text/fragment+html; charset=utf-8",
		},
		{
			char:  "utf-8",
			media: "application/json",
			res:   "application/json; charset=utf-8",
		},
		{
			char:  "",
			media: "application/json",
			res:   "application/json",
		},
	}

	for _, v := range c {
		client.ContentType.MediaType = v.media
		client.ContentType.Charset = v.char

		r := client.GetContentType()

		tError(r != v.res, fmt.Sprintf("Oups, bad URI reply\nExpect: %s, Give: %s\n%#v\n", v.res, r, client), t)
	}
}

func TestRequest(t *testing.T) {
	c := []struct {
		cli rapic.Client
		res string
		err string
	}{
		{
			cli: rapic.Client{
				Method:   rapic.METHOD_GET,
				Scheme:   "https",
				Endpoint: "google.com",
			},
			res: "200 OK",
		},
		{
			cli: rapic.Client{
				Method:   rapic.METHOD_GET,
				Scheme:   "https",
				Endpoint: "google.local",
			},
			err: `Get "https://google.local": dial tcp: lookup google.local: no such host`,
		},
	}

	for _, v := range c {
		r, err := v.cli.Request()

		tError(err != nil && err.Error() != v.err, fmt.Sprintf("Oups, unexpected error\n%v\n%#v\n", err, r), t)
		tError(r.Status != v.res, fmt.Sprintf("Oups, bad request result\nExpect: %s, Give: %s\n", r.Status, v.res), t)
	}
}
