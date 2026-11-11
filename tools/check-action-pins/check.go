package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Finding is one `uses` key (or one unreadable key) that is not pinned.
type Finding struct {
	Line   int    // line of the key, 1-based; 0 if unknown (parse error)
	Reason string // why it is reported
	Value  string // the value as written, or a description of it
}

func (f Finding) String() string {
	return fmt.Sprintf("%d: %s: uses: %s", f.Line, f.Reason, f.Value)
}

// The accepted values of a `uses` key. These are the patterns of the former
// scripts/check-action-pins.sh.
var (
	actionRef      = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@\s]+)?@[0-9a-f]{40}$`)
	versionComment = regexp.MustCompile(`^#[ \t]*v[0-9]+\.[0-9]+\.[0-9]+([^0-9.]|$)`)
	localAction    = regexp.MustCompile(`^\./`)
	dockerDigest   = regexp.MustCompile(`^docker://[^@\s]+@sha256:[0-9a-f]{64}$`)
)

const (
	reasonFlow       = "uses in a flow mapping or sequence; write it in block style"
	reasonAliasKey   = "alias %s used as a mapping key; write the key out"
	reasonTaggedKey  = "mapping key %s has a tag other than !!str; write the key out"
	reasonAliasValue = "alias as the value; write the value out"
	reasonNotString  = "value is not a plain string"
	reasonBlock      = "block scalar; write the value on one line"
	reasonNotPinned  = "not pinned to a full commit SHA with a '# vX.Y.Z' comment (or a docker:// digest)"
)

// Check parses src, every YAML document in it, and reports every `uses` key
// whose value is not pinned, plus every mapping key it cannot read as a
// plain string. All rules work on the parsed node tree, never on the text.
// A file that does not parse is an error.
func Check(src []byte) ([]Finding, error) {
	var findings []Finding
	dec := yaml.NewDecoder(bytes.NewReader(src))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return findings, nil
		}
		if err != nil {
			return findings, err
		}
		findings = walk(&doc, false, findings)
	}
}

// LocalActions returns the values of the `uses` keys in src that name a
// local action (`./path`), so the caller can scan their action files too.
// It assumes src parses (Check reported nothing else).
func LocalActions(src []byte) []string {
	var paths []string
	dec := yaml.NewDecoder(bytes.NewReader(src))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			return paths
		}
		paths = collectLocal(&doc, paths)
	}
}

func collectLocal(n *yaml.Node, paths []string) []string {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind == yaml.ScalarNode && k.Value == "uses" && v.Kind == yaml.ScalarNode && localAction.MatchString(v.Value) {
				paths = append(paths, v.Value)
			}
		}
	}
	for _, c := range n.Content {
		paths = collectLocal(c, paths)
	}
	return paths
}

// walk visits every node. Aliases are not followed: the node an alias points
// to is checked where its anchor defines it, so every key in the file is
// checked exactly once. inFlow is true inside a flow mapping or sequence.
func walk(n *yaml.Node, inFlow bool, findings []Finding) []Finding {
	if (n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) && n.Style&yaml.FlowStyle != 0 {
		inFlow = true
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if f, ok := checkPair(n.Content[i], n.Content[i+1], inFlow); ok {
				findings = append(findings, f)
			}
		}
	}
	for _, c := range n.Content {
		findings = walk(c, inFlow, findings)
	}
	return findings
}

// checkPair checks one key/value pair of a mapping. It returns a finding
// for an unreadable key, and for a `uses` key whose value is not pinned.
func checkPair(k, v *yaml.Node, inFlow bool) (Finding, bool) {
	// An alias key resolves to whatever its anchor holds, which may be
	// `uses` (GitHub and actionlint resolve it). Rejecting it is simpler
	// than resolving it, and fails closed.
	if k.Kind == yaml.AliasNode {
		return Finding{k.Line, fmt.Sprintf(reasonAliasKey, "*"+k.Value), describe(v)}, true
	}
	if k.Kind != yaml.ScalarNode {
		return Finding{}, false
	}
	// A tagged key such as `!!binary dXNlcw==` may decode to `uses`.
	if k.Style&yaml.TaggedStyle != 0 && k.Tag != "!!str" {
		return Finding{k.Line, fmt.Sprintf(reasonTaggedKey, k.Tag+" "+k.Value), describe(v)}, true
	}
	// k.Value is the decoded key: quotes, escapes (`"u\x73es"`) and the
	// explicit-key form (`? uses`) are already resolved by the parser.
	if k.Value != "uses" {
		return Finding{}, false
	}
	if inFlow {
		return Finding{k.Line, reasonFlow, describe(v)}, true
	}
	switch {
	case v.Kind == yaml.AliasNode:
		return Finding{k.Line, reasonAliasValue, describe(v)}, true
	case v.Kind != yaml.ScalarNode || v.Tag != "!!str":
		return Finding{k.Line, reasonNotString, describe(v)}, true
	case v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return Finding{k.Line, reasonBlock, describe(v)}, true
	}
	if localAction.MatchString(v.Value) || dockerDigest.MatchString(v.Value) {
		return Finding{}, false
	}
	// The version comment must be the value node's own line comment: a
	// real YAML comment after the value, on the value's line. Text inside a
	// quoted string is part of the value, not a comment.
	if actionRef.MatchString(v.Value) && versionComment.MatchString(v.LineComment) {
		return Finding{}, false
	}
	return Finding{k.Line, reasonNotPinned, describe(v)}, true
}

// describe gives a value for the report: the scalar as written, or what
// kind of node it is.
func describe(v *yaml.Node) string {
	switch v.Kind {
	case yaml.AliasNode:
		return "*" + v.Value
	case yaml.ScalarNode:
		s := v.Value
		if v.Style&yaml.TaggedStyle != 0 {
			s = v.Tag + " " + s
		}
		return strings.TrimSpace(strings.ReplaceAll(s, "\n", `\n`))
	case yaml.MappingNode:
		return "(a mapping)"
	case yaml.SequenceNode:
		return "(a sequence)"
	}
	return "(unknown)"
}
