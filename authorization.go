package rapic

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"net/url"
	"strings"
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
