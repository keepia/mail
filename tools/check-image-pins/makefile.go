package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The Makefile side of rule 5 (#43 round 3): `make images` may change the
// bake definition only in ways the check allows. The checked text is
// every line that runs `buildx bake`, plus the definitions of the make
// variables it uses (transitively). In it:
//   - no -f/--file (the default files are the ones the check resolves);
//   - --set keys only from makeSetKeys;
// and nowhere in a Makefile any BUILDX_ variable (BUILDX_BAKE_FILE and
// the like steer bake without a flag).

// makeSetKeys are the --set keys `make images` may use, each needed for a
// local build behind a TLS-inspecting proxy (KEEPIA_BUILD_CA) and none
// touching context, contexts, dockerfile, dockerfile-inline or args other
// than the proxy:
//   - *.secrets: the CA bundle as the BuildKit secret "ca";
//   - *.network: the host network, so the build reaches the local proxy;
//   - *.args.HTTPS_PROXY: the proxy, a predefined build argument kept out
//     of the image history.
var makeSetKeys = map[string]bool{"*.secrets": true, "*.network": true, "*.args.HTTPS_PROXY": true}

var (
	makeVarDef = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\?=|:=|::=|\+=|=)(.*)$`)
	makeVarRef = regexp.MustCompile(`\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]`)
)

type makeLine struct {
	line int
	text string
}

// makeLogicalLines joins backslash continuations and drops comments.
func makeLogicalLines(src []byte) []makeLine {
	var out []makeLine
	var cur *makeLine
	for i, raw := range strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if cur == nil && strings.HasPrefix(trimmed, "#") {
			continue
		}
		body := strings.TrimSuffix(strings.TrimRight(raw, " \t"), `\`)
		if cur == nil {
			out = append(out, makeLine{line: i + 1, text: body})
			cur = &out[len(out)-1]
		} else {
			cur.text += " " + strings.TrimSpace(body)
		}
		if !strings.HasSuffix(strings.TrimRight(raw, " \t"), `\`) {
			cur = nil
		}
	}
	return out
}

// CheckMakefile applies the Makefile side of rule 5.
func CheckMakefile(src []byte) []Finding {
	lines := makeLogicalLines(src)
	var out []Finding
	add := func(line int, format string, a ...any) {
		out = append(out, Finding{line, fmt.Sprintf(format, a...)})
	}
	defs := map[string][]makeLine{}
	for _, l := range lines {
		if strings.Contains(l.text, "BUILDX_") {
			add(l.line, "BUILDX_ variables steer buildx without a flag the check can see; do not set them in a Makefile")
		}
		if m := makeVarDef.FindStringSubmatch(strings.TrimSpace(l.text)); m != nil && !strings.HasPrefix(l.text, "\t") {
			defs[m[1]] = append(defs[m[1]], makeLine{l.line, m[2]})
		}
	}
	// The bake lines and, transitively, the variables they use.
	var checked []makeLine
	seen := map[string]bool{}
	var queue []string
	for _, l := range lines {
		if strings.Contains(strings.Join(strings.Fields(l.text), " "), "buildx bake") {
			checked = append(checked, l)
			for _, m := range makeVarRef.FindAllStringSubmatch(l.text, -1) {
				queue = append(queue, m[1])
			}
		}
	}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		if seen[v] {
			continue
		}
		seen[v] = true
		for _, d := range defs[v] {
			checked = append(checked, d)
			for _, m := range makeVarRef.FindAllStringSubmatch(d.text, -1) {
				queue = append(queue, m[1])
			}
		}
	}
	sort.SliceStable(checked, func(i, j int) bool { return checked[i].line < checked[j].line })
	for _, l := range checked {
		words := strings.Fields(l.text)
		for i, w := range words {
			switch {
			case w == "-f" || w == "--file" || strings.HasPrefix(w, "--file=") || (strings.HasPrefix(w, "-f") && !strings.HasPrefix(w, "--")):
				add(l.line, "bake %s: a bake file other than the defaults is not resolved by the check", w)
			case w == "--set" || strings.HasPrefix(w, "--set="):
				v := strings.TrimPrefix(w, "--set=")
				if w == "--set" {
					v = ""
					if i+1 < len(words) {
						v = words[i+1]
					}
				}
				v = strings.Trim(v, `'"`)
				key, _, _ := strings.Cut(v, "=")
				if !makeSetKeys[key] {
					add(l.line, "bake --set %q: only %s may be set by the Makefile", key, strings.Join(sortedBool(makeSetKeys), ", "))
				}
			}
		}
	}
	return out
}
