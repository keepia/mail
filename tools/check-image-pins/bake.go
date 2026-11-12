package main

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// bakeAttr is an HCL attribute assignment at the start of a line.
	bakeAttr = regexp.MustCompile(`^\s*"?([A-Za-z_][A-Za-z0-9_-]*)"?\s*=(.*)$`)
	// bakeLocalContext is a context given as a plain relative path literal.
	bakeLocalContext = regexp.MustCompile(`^"([A-Za-z0-9_.][A-Za-z0-9_./-]*)"\s*(?:#.*|//.*)?$`)
)

// CheckBake applies rule 5 of the image pin check to a docker-bake.hcl.
// It reads lines, not HCL: every `context = ` must be a relative path
// literal inside the repository, and the attributes that can pull images
// or sources this check does not see are reported wherever they appear:
// `contexts` (named contexts such as docker-image://), `dockerfile-inline`
// and a BUILDKIT_SYNTAX build argument (it overrides # syntax=). A
// multi-line string (heredoc) is reported too, because its lines are not
// attributes.
func CheckBake(src []byte) []Finding {
	var out []Finding
	add := func(line int, format string, a ...any) {
		out = append(out, Finding{line, fmt.Sprintf(format, a...)})
	}
	for i, raw := range strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.Contains(line, "<<") {
			add(n, "a heredoc is not read by this check")
		}
		if strings.Contains(line, "BUILDKIT_SYNTAX") {
			add(n, "BUILDKIT_SYNTAX overrides the pinned # syntax= directive")
		}
		m := bakeAttr.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch m[1] {
		case "contexts":
			add(n, "contexts is not allowed: a named context can pull an image or source this check does not see")
		case "dockerfile-inline":
			add(n, "dockerfile-inline is not read by this check; use a Dockerfile")
		case "context":
			v := strings.TrimSpace(m[2])
			cm := bakeLocalContext.FindStringSubmatch(v)
			if cm == nil || !isLocalContext(cm[1]) {
				add(n, "context %s is not a relative path literal inside the repository", v)
			}
		}
	}
	return out
}
