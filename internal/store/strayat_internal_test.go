package store

import "testing"

// strayAt fails closed on every URL whose user information holds an
// unescaped '@', '/', '?' or '#' before an '@', and leaves well-formed
// URLs and the keyword/value form alone.
func TestStrayAt(t *testing.T) {
	for s, want := range map[string]bool{
		// Stray '@'.
		"postgres://u:pa@ss@h:1/k":            true,
		"postgres://u:pa@ss/word@h:1/k":       true,
		"postgres://u:pa@ss?x=word@h:1/k":     true,
		"postgres://u:pa@ss#word@h:1/k":       true,
		"postgresql://u:pa@ss@h:1/k":          true,
		"postgres://u:5432/word@h/k":          true, // '/' in the password: the '@' lands in the path
		"postgres://u:pa?ss=word@h/k":         true, // '?' in the password: the '@' lands in the query
		"postgres://h/k?application_name=a@b": true, // fails closed: an '@' outside the authority
		// Well-formed.
		"postgres://u:pa%40ss%2Fword@h:1/k": false,
		"postgres://u:pw@h:1,h2:2/k":        false,
		"postgresql://u@h/k":                false,
		"postgres://h/k":                    false,
		"postgres:///k?host=/run/pg":        false,
	} {
		if got := strayAt(s); got != want {
			t.Errorf("strayAt(%q) = %v, want %v", s, got, want)
		}
	}
}

// isURL accepts only strings that pgx parses as a URL: exactly
// postgres:// or postgresql:// in front, no white space around them.
func TestIsURL(t *testing.T) {
	for s, want := range map[string]bool{
		"postgres://u:pw@h/k":                   true,
		"postgresql://u:pw@h/k":                 true,
		"postgres:///k":                         true,
		" postgres://u:pw@h/k?sslmode=disable":  false,
		"postgres://u:pw@h/k\t":                 false,
		"POSTGRES://u:pw@h/k?sslmode=disable":   false,
		"Postgres://u:pw@h/k":                   false,
		"postgres:/u:pw@h/k":                    false,
		"postgres:u:pw@h/k":                     false,
		"host=h user=u password=pa host=x":      false,
		"user=u password=pw postgres://u:pw@h/": false,
		"":                                      false,
	} {
		if got := isURL(s); got != want {
			t.Errorf("isURL(%q) = %v, want %v", s, got, want)
		}
	}
}
