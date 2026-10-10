// Package apipath splits request URLs into path and query parameters and
// normalizes paths into API templates (/users/123 -> /users/{id}), so all
// requests to one endpoint count as one API asset.
package apipath

import (
	"net/url"
	"strings"
)

// maxQueryParams bounds the query parameters kept per request.
const maxQueryParams = 100

// Split separates a request target ("/a/b?x=1#f") into its path and query
// parameters. Repeated parameters keep their first value. The path is
// returned unescaped only where that is lossless.
func Split(target string) (string, map[string]string) {
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target = target[:i]
	}
	path, rawQuery, hasQuery := strings.Cut(target, "?")
	if p, err := url.PathUnescape(path); err == nil && !strings.Contains(p, "?") {
		path = p
	}
	if !hasQuery || rawQuery == "" {
		return path, nil
	}
	params := make(map[string]string)
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" || len(params) >= maxQueryParams {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		if k == "" {
			continue
		}
		if _, seen := params[k]; !seen {
			params[k] = v
		}
	}
	if len(params) == 0 {
		return path, nil
	}
	return path, params
}

// Normalize turns a path into an API template by replacing segments that
// identify a resource: all digits (also when partly masked by redaction,
// such as 138****8000) -> {id}, a UUID -> {uuid}, a long hex string
// (hashes, object IDs) -> {hash}. Any query string is dropped.
func Normalize(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" || path == "/" {
		return path
	}
	parts := strings.Split(path, "/")
	for i, seg := range parts {
		if seg == "" {
			continue
		}
		switch {
		case isDigits(seg), isMaskedDigits(seg):
			parts[i] = "{id}"
		case isUUID(seg):
			parts[i] = "{uuid}"
		case len(seg) >= 16 && isHex(seg):
			parts[i] = "{hash}"
		}
	}
	return strings.Join(parts, "/")
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// isMaskedDigits reports a digit string partly replaced by '*' during
// redaction.
func isMaskedDigits(s string) bool {
	digits, stars := 0, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			digits++
		case s[i] == '*':
			stars++
		default:
			return false
		}
	}
	return digits > 0 && stars > 0
}

// IsIdentifier reports whether a path segment identifies a resource and is
// replaced by Normalize.
func IsIdentifier(seg string) bool {
	return seg != "" && Normalize("/"+seg) != "/"+seg
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return s != ""
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
		} else if !isHex(s[i : i+1]) {
			return false
		}
	}
	return true
}
