package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// directive is a parser directive line at the top of a Dockerfile:
// `# key=value` (BuildKit's form; keys are case-insensitive).
var directive = regexp.MustCompile(`^#[ \t]*([A-Za-z][A-Za-z0-9_-]*)[ \t]*=[ \t]*(.*?)[ \t]*$`)

// heredoc is the start of a BuildKit here-document (`<<EOF`, `<<-"EOF"`).
// Its body lines are not instructions, and this checker does not track
// where it ends, so a here-document is reported instead of read.
var heredoc = regexp.MustCompile(`<<-?["']?[A-Za-z_]`)

// platformVars are the only variables a FROM --platform flag may carry.
var platformVars = map[string]bool{
	"$BUILDPLATFORM": true, "${BUILDPLATFORM}": true,
	"$TARGETPLATFORM": true, "${TARGETPLATFORM}": true,
}

// instruction is one logical Dockerfile line: the physical lines joined at
// their trailing backslashes, without the comment and empty lines that
// BuildKit drops inside a continuation.
type instruction struct {
	line  int      // first physical line
	text  string   // the joined text
	parts []string // the physical lines that make it up
}

// CheckDockerfile applies rules 1-3 of the image pin check to a Dockerfile:
//  1. a `# syntax=` directive pinned as name:X.Y.Z@sha256:<64 hex>;
//  2. every FROM, COPY --from= and RUN --mount=...,from= names an earlier
//     stage or name:tag@sha256:<64 hex>; only FROM --platform may carry a
//     variable ($BUILDPLATFORM, $TARGETPLATFORM); a FROM that continues on
//     the next line, and COPY or RUN flags that do, are reported;
//  3. every ADD from http(s):// carries --checksum=sha256:<64 hex>; ADD of
//     a git URL is reported.
//
// Forms it cannot read fail closed: an escape directive other than the
// backslash, a here-document and ONBUILD are reported.
func CheckDockerfile(src []byte) []Finding {
	lines := strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n")
	var out []Finding
	add := func(line int, format string, a ...any) {
		out = append(out, Finding{line, fmt.Sprintf(format, a...)})
	}

	// Parser directives: the leading lines of the form `# key=value`.
	start := 0
	syntax := false
	for ; start < len(lines); start++ {
		m := directive.FindStringSubmatch(lines[start])
		if m == nil {
			break
		}
		switch strings.ToLower(m[1]) {
		case "syntax":
			syntax = true
			if !pinnedSyntax.MatchString(m[2]) {
				add(start+1, "# syntax=%s is not pinned as name:X.Y.Z@sha256:<64 hex>", m[2])
			}
		case "escape":
			if m[2] != `\` {
				add(start+1, "escape directive %q is not read; only the backslash is", m[2])
				return out
			}
		}
	}
	if !syntax {
		add(1, "no # syntax= directive; pin the frontend as # syntax=docker/dockerfile:X.Y.Z@sha256:<64 hex>")
	}

	stages := map[string]bool{} // stage names, lowercased
	nStages := 0
	for _, in := range instructions(lines, start) {
		if heredoc.MatchString(in.text) {
			add(in.line, "here-document is not read by this check; use a COPY'd script instead")
			return out
		}
		fields := strings.Fields(in.text)
		kw := strings.ToUpper(fields[0])
		args := fields[1:]
		switch kw {
		case "ONBUILD":
			add(in.line, "ONBUILD is not read by this check")
		case "FROM":
			if len(in.parts) > 1 {
				add(in.line, "FROM continues on the next line; write it on one line")
				continue
			}
			checkFrom(in.line, args, stages, add)
			// The stage counts even when the line was reported, so later
			// numeric references stay aligned with BuildKit's.
			nStages++
			if len(args) >= 2 && strings.EqualFold(args[len(args)-2], "AS") {
				stages[strings.ToLower(args[len(args)-1])] = true
			}
		case "COPY", "RUN", "ADD":
			if flagsContinue(in) {
				add(in.line, "%s has a --flag on a continuation line; put every --flag on the instruction's first line", kw)
			}
			flags, rest := splitFlags(args)
			switch kw {
			case "COPY":
				for _, v := range flagValues(flags, "--from") {
					checkStageRef(in.line, "COPY --from", v, stages, nStages, add)
				}
			case "RUN":
				for _, v := range flagValues(flags, "--mount") {
					for _, kv := range strings.Split(v, ",") {
						k, val, _ := strings.Cut(kv, "=")
						if strings.EqualFold(strings.TrimSpace(k), "from") {
							checkStageRef(in.line, "RUN --mount from", strings.Trim(val, `"'`), stages, nStages, add)
						}
					}
				}
			case "ADD":
				checkAdd(in, flags, rest, add)
			}
		}
	}
	return out
}

// instructions joins the physical lines from index start into logical
// instructions. Comment and empty lines outside an instruction are skipped,
// and so are those inside a continuation, as BuildKit does.
func instructions(lines []string, start int) []instruction {
	var out []instruction
	var cur *instruction
	for i := start; i < len(lines); i++ {
		raw := strings.TrimRight(lines[i], " \t")
		trimmed := strings.TrimLeft(raw, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		cont := strings.HasSuffix(raw, `\`)
		body := strings.TrimSuffix(raw, `\`)
		if cur == nil {
			out = append(out, instruction{line: i + 1})
			cur = &out[len(out)-1]
			cur.text = body
		} else {
			cur.text += " " + body
		}
		cur.parts = append(cur.parts, body)
		if !cont {
			cur = nil
		}
	}
	return out
}

// flagsContinue reports whether one of an instruction's --flags sits on a
// continuation line: a flag after the first physical line, before the
// first word that is not a flag. The joined text reads it as BuildKit
// does, but the plan keeps every flag on the first line so a reader (and
// a line-based tool such as scripts/ci-pull-images.sh) sees them there.
// A first line that holds only flags, followed by the command, is fine.
func flagsContinue(in instruction) bool {
	for i, part := range in.parts {
		words := strings.Fields(part)
		if i == 0 {
			words = words[1:]
		}
		for _, w := range words {
			if !strings.HasPrefix(w, "--") {
				return false
			}
			if i > 0 {
				return true
			}
		}
	}
	return false
}

// splitFlags splits the words after the keyword into the leading --flags
// and the rest.
func splitFlags(args []string) (flags, rest []string) {
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "--") {
		i++
	}
	return args[:i], args[i:]
}

// flagValues returns the value of every --name=value flag. A bare --name
// gives "", which the caller reports.
func flagValues(flags []string, name string) []string {
	var vals []string
	for _, f := range flags {
		k, v, ok := strings.Cut(f, "=")
		if !strings.EqualFold(k, name) {
			continue
		}
		if !ok {
			v = ""
		}
		vals = append(vals, v)
	}
	return vals
}

func checkFrom(line int, args []string, stages map[string]bool, add func(int, string, ...any)) {
	flags, rest := splitFlags(args)
	for _, f := range flags {
		k, v, _ := strings.Cut(f, "=")
		if !strings.EqualFold(k, "--platform") {
			add(line, "FROM flag %s is not read by this check", k)
			continue
		}
		if strings.Contains(v, "$") && !platformVars[v] {
			add(line, "FROM --platform=%s: only $BUILDPLATFORM or $TARGETPLATFORM may be a variable", v)
		}
	}
	switch {
	case len(rest) == 0:
		add(line, "FROM without an image")
		return
	case len(rest) == 2 || len(rest) > 3 || (len(rest) == 3 && !strings.EqualFold(rest[1], "AS")):
		add(line, "FROM is not of the form FROM [--platform=...] image [AS name]")
		return
	}
	image := rest[0]
	if stages[strings.ToLower(image)] || image == "scratch" {
		return
	}
	if !isPinnedImage(image) {
		add(line, "%s", unpinnedMsg("FROM image", image))
	}
}

// checkStageRef checks a --from value: an earlier stage by name or index,
// or a pinned image.
func checkStageRef(line int, what, ref string, stages map[string]bool, nStages int, add func(int, string, ...any)) {
	if ref == "" {
		add(line, "%s has no value", what)
		return
	}
	if stages[strings.ToLower(ref)] {
		return
	}
	if n, err := strconv.Atoi(ref); err == nil {
		if n >= 0 && n < nStages {
			return
		}
		add(line, "%s=%s names no earlier stage", what, ref)
		return
	}
	if !isPinnedImage(ref) {
		add(line, "%s", unpinnedMsg(what, ref))
	}
}

// isGitSource reports whether an ADD source is a git repository, which
// BuildKit clones: git@ and git:// URLs, a URL path ending in .git, and a
// URL with a #ref fragment.
func isGitSource(s string) bool {
	l := strings.ToLower(s)
	if strings.HasPrefix(l, "git@") || strings.HasPrefix(l, "git://") || strings.HasPrefix(l, "ssh://") {
		return true
	}
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return false
	}
	path, _, hasFrag := strings.Cut(l, "#")
	return hasFrag || strings.HasSuffix(strings.SplitN(path, "?", 2)[0], ".git")
}

func checkAdd(in instruction, flags, rest []string, add func(int, string, ...any)) {
	var checksum []string
	for _, f := range flags {
		k, v, _ := strings.Cut(f, "=")
		switch strings.ToLower(k) {
		case "--checksum":
			checksum = append(checksum, v)
		case "--keep-git-dir":
			add(in.line, "ADD --keep-git-dir: ADD of a git repository is not allowed")
		}
	}
	srcs := rest
	if len(rest) > 0 && strings.HasPrefix(rest[0], "[") {
		// JSON form: the whole remainder is one array.
		joined := strings.Join(rest, " ")
		var arr []string
		if err := json.Unmarshal([]byte(joined), &arr); err != nil {
			add(in.line, "ADD JSON form does not parse: %v", err)
			return
		}
		srcs = arr
	}
	if len(srcs) < 2 {
		add(in.line, "ADD needs a source and a destination")
		return
	}
	srcs = srcs[:len(srcs)-1]
	urls := 0
	for _, s := range srcs {
		l := strings.ToLower(s)
		if isGitSource(s) {
			add(in.line, "ADD of a git URL (%s) is not allowed; ADD a release archive with --checksum", s)
			continue
		}
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			urls++
		}
	}
	if urls == 0 {
		return
	}
	if urls > 1 {
		add(in.line, "ADD with %d URLs; ADD one URL per instruction, each with its own --checksum", urls)
		return
	}
	if len(checksum) != 1 || !sha256Checksum.MatchString(checksum[0]) {
		add(in.line, "ADD from a URL needs --checksum=sha256:<64 hex>")
	}
}
