package rapic

import (
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func printCookies(c []*http.Cookie) (res string) {
	for i, v := range c {
		res = fmt.Sprintf("\n- Cookie[%d]: %#v", i, *v)
	}

	return
}

func tError(r bool, s string, t *testing.T) {
	if r {
		_, f, l, ok := runtime.Caller(1)
		if !ok {
			f, l = "", 0
		}
		t.Errorf("\n[%s:%d]: %s", f, l, s)
		t.Fail()
	}
}

func TestSatus(t *testing.T) {
	test := []struct {
		code   int
		expect bool
	}{
		{0, false},
		{100, false},
		{200, true},
		{226, true},
		{300, true},
		{310, true},
		{400, false},
		{418, false},
		{505, false},
		{527, false},
	}

	for _, v := range test {
		tError(reqIsSuccess(v.code) != v.expect, fmt.Sprint("Code: ", v.code, ", Expect: ", v.expect, ", Returned: ", !v.expect), t)
	}
}

func TestPath(t *testing.T) {
	test := []struct {
		path   string
		expect string
	}{
		{"", ""},
		{"/", ""},
		{"Vault 13/Water Chip/Necropolis", "/Vault 13/Water Chip/Necropolis"},
		{"Vault 13/Water Chip/Necropolis/", "/Vault 13/Water Chip/Necropolis"},
		{"/Vault 13/Water Chip/Necropolis", "/Vault 13/Water Chip/Necropolis"},
		{"/Vault 13/Water Chip/Necropolis/", "/Vault 13/Water Chip/Necropolis"},
		{"Vault%2013/Water%20Chip/Necropolis", "/Vault%2013/Water%20Chip/Necropolis"},
		{"Vault%2013/Water%20Chip/Necropolis/", "/Vault%2013/Water%20Chip/Necropolis"},
		{"/Vault%2013/Water%20Chip/Necropolis", "/Vault%2013/Water%20Chip/Necropolis"},
		{"/Vault%2013/Water%20Chip/Necropolis/", "/Vault%2013/Water%20Chip/Necropolis"},
		{"MINSC_HAS_A_NEW_WITCH", "/MINSC_HAS_A_NEW_WITCH"},
		{"MINSC_HAS_A_NEW_WITCH/", "/MINSC_HAS_A_NEW_WITCH"},
		{"/MINSC_HAS_A_NEW_WITCH", "/MINSC_HAS_A_NEW_WITCH"},
		{"/MINSC_HAS_A_NEW_WITCH/", "/MINSC_HAS_A_NEW_WITCH"},
		{"https://why.not/my/api", "/https://why.not/my/api"},
		{"https://why.not/my/api/", "/https://why.not/my/api"},
		{"//why.not/my/api/", "/why.not/my/api"},
		{"//why.not/my/api", "/why.not/my/api"},
	}

	for _, v := range test {
		res := pathFormatting(v.path)
		tError((v.expect) != res, fmt.Sprint("Path: ", v.path, ", Expect: ", v.expect, ", Returned: ", res), t)
	}
}

func TestCookieKeyVal(t *testing.T) {
	test := []struct {
		pair  string
		key   string
		value string
	}{
		{"", "", ""},
		{"_bit=l9dlTC-404617dcd208b18551-00p", "_bit", "l9dlTC-404617dcd208b18551-00p"},
		{"fbm_124095374287414=base_domain=.instagram.com", "fbm_124095374287414", "base_domain=.instagram.com"},
		{"Musculus=-____---______)))((**&&=&^^%%$$##@#@!!?><><:}{|][';/.,,--===``~", "Musculus", "-____---______)))((**&&=&^^%%$$##@#@!!?><><:}{|][';/.,,--===``~"},
		{"MaltMe=isIABGlobal=false&datestamp=Wed+Oct+13+2021+23%3A42%3A36+GMT%2B0200+(heure+d%E2%80%99%C3%A9t%C3%A9+d%E2%80%99Europe+centrale)&version=6.10.0", "MaltMe", "isIABGlobal=false&datestamp=Wed+Oct+13+2021+23%3A42%3A36+GMT%2B0200+(heure+d%E2%80%99%C3%A9t%C3%A9+d%E2%80%99Europe+centrale)&version=6.10.0"},
		{"privacySettings=%7B%22v%22%3A%221%22%2C%22t%22%3A1633651200%2C%22m%22%3A%22STRICT%22%2C%22consent%22%3A%5B%22NECESSARY%22%2C%22PERFORMANCE%22%2C%22COMFORT%22%5D%7D", "privacySettings", "%7B%22v%22%3A%221%22%2C%22t%22%3A1633651200%2C%22m%22%3A%22STRICT%22%2C%22consent%22%3A%5B%22NECESSARY%22%2C%22PERFORMANCE%22%2C%22COMFORT%22%5D%7D"},
	}

	for _, v := range test {
		ck, cv := cookieKeyValue(v.pair)
		tError(ck != v.key || cv != v.value, fmt.Sprint("Pair: ", v.pair, ", Expect: ", v.key, " => ", v.value, ", Returned: ", ck, " => ", cv), t)
	}
}

func TestCookieExpires(t *testing.T) {
	test := []struct {
		rawTime string
		expect  string
	}{
		{"", "0001-01-01 00:00:00 +0000 UTC"},
		{"Tue, 30 Sep 1997 0:01:55 UTC", "1997-09-30 00:01:55 +0000 UTC"},
		{"Thu, 29 Oct 1998 12:54:00 -0700", "1998-10-29 12:54:00 -0700 -0700"},
		{"Friday, 18-Dec-15 15:04:05 GTM", "2015-12-18 15:04:05 +0000 GTM"},
		{"Wed, 06-Feb-1985 23:00:45 MST", "1985-02-06 23:00:45 +0000 MST"},
		{"Monday 06 August 1945 08:15:00 +0200", "0001-01-01 00:00:00 +0000 UTC"},
	}

	for _, v := range test {
		outTime, _ := cookieExpires(v.rawTime)
		tError(outTime.String() != v.expect, fmt.Sprint("Pair: ", v.rawTime, ", Expect: ", v.expect, ", Returned: ", outTime.String()), t)
	}
}

func TestCookie(t *testing.T) {
	test := []struct {
		raw    []string
		cookie []*http.Cookie
	}{
		{
			[]string{"XSRF=Ma~VWVbrFfbWk5SA.4t44; Expires=Mon, 13-Dec-2021 14:09:12 UTC; Path=/test/; SameSite=Lax; ThinkNot"},
			[]*http.Cookie{{Name: "XSRF", Value: "Ma~VWVbrFfbWk5SA.4t44", Path: "/test/", Expires: time.Date(2021, time.December, 13, 14, 9, 12, 0, time.UTC), RawExpires: "Mon, 13-Dec-2021 14:09:12 UTC", SameSite: http.SameSiteLaxMode, Unparsed: []string{"ThinkNot"}}},
		},
		{
			[]string{"_history=datestamp=Tue+Sep+28+2021+20%3A38%3A39+GMT%2B0200+(heure+d%E2%80%99%C3%A9t%C3%A9+d%E2%80%99Europe+centrale)&version=6.23.0; Path=/; HttpOnly"},
			[]*http.Cookie{{Name: "_history", Value: "datestamp=Tue+Sep+28+2021+20%3A38%3A39+GMT%2B0200+(heure+d%E2%80%99%C3%A9t%C3%A9+d%E2%80%99Europe+centrale)&version=6.23.0", Path: "/", HttpOnly: true}},
		},
		{
			[]string{"SESSION=6d44_7bc97tr5912a; Max-Age=oups; SameSite=Strict; Secure; HttpOnly"},
			[]*http.Cookie{{Name: "SESSION", Value: "6d44_7bc97tr5912a", MaxAge: 0, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}},
		},
		{
			[]string{"visitor-id=6d563a1e4ad27bc97bf5912a; Max-Age=5259600; Path=/bim/bam~boom; SameSite=BOUM"},
			[]*http.Cookie{{Name: "visitor-id", Value: "6d563a1e4ad27bc97bf5912a", Path: "/bim/bam~boom", MaxAge: 5259600, SameSite: http.SameSiteDefaultMode}},
		},
		{
			[]string{"v_id=9d553a1e-5e5ce6a203a42669f5f5a4c; Expires=Mon, 13 Dec 2021 14:09:12 UTC; SameSite=None; domain=.my.test; templateVariant=CO; flixgvid=flixec0b7abf000000.48803159"},
			[]*http.Cookie{{Name: "v_id", Value: "9d553a1e-5e5ce6a203a42669f5f5a4c", Domain: ".my.test", Expires: time.Date(2021, time.December, 13, 14, 9, 12, 0, time.UTC), RawExpires: "Mon, 13 Dec 2021 14:09:12 UTC", SameSite: http.SameSiteNoneMode, Unparsed: []string{"templateVariant=CO", "flixgvid=flixec0b7abf000000.48803159"}}},
		},
	}

	for _, v := range test {
		miniJar := cookieParse(v.raw)
		tError(!reflect.DeepEqual(v.cookie, miniJar), fmt.Sprintf("Cookie Raw: %s\nCookie Expected: %s\nCookie Gived: %s\n\n", v.raw, printCookies(v.cookie), printCookies(miniJar)), t)
	}
}

func TestIsASCII(t *testing.T) {
	test := []struct {
		g string
		e bool
	}{
		{"", true},
		{"/", true},
		{"Je suis une Water Chip !?", true},
		{"No, you're not !", true},
		{"Minsc_and_Boo", true},
		{"اركانوم: اوف ستايموركس اند ماجيك اوبسكورا", false},
		{"עטיפת המשחק", false},
		{"Линукс", false},
		{"维基百科", false},
		{"нo my ******* striתg", false},
	}

	for _, v := range test {
		tError(isASCII(v.g) != v.e, fmt.Sprint("String: ", v.g, ", Expect: ", v.e, ", Returned: ", !v.e), t)
	}
}
