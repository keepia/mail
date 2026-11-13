package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ownImageForm is how an own image is named in the Compose file, so the
// release bundle can pin it (part 4): under the registry variable with
// exactly the default ghcr.io/keepia, as mail or mail-<name>, with an
// optional literal tag or ${KEEPIA_VERSION:-<tag>}. The whole name must
// match: a check of only the prefix ${KEEPIA_REGISTRY let
// ${KEEPIA_REGISTRY:-docker.io/evil} and ${KEEPIA_REGISTRYX:-busybox}
// through (#61). The values set at run time are not checked here.
const ownImageForm = "${KEEPIA_REGISTRY:-ghcr.io/keepia}/mail[-<name>][:<tag>|:${KEEPIA_VERSION:-<tag>}]"

var ownImageNameRE = regexp.MustCompile(`^\$\{KEEPIA_REGISTRY:-ghcr\.io/keepia\}/mail(?:-[a-z0-9]+)?` +
	`(?::(?:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|\$\{KEEPIA_VERSION:-[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\}))?$`)

// parseYAML parses every document of src. It returns the document nodes,
// or an error when src does not parse.
func parseYAML(src []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var docs []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		docs = append(docs, &n)
	}
}

// mappingValue returns the value node of key in a mapping node, following
// an alias, and the key node; nil if the key is not there. A merge key
// (`<<`) is not followed: callers decode the value to see merged keys.
func mappingValue(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v := m.Content[i+1]
			if v.Kind == yaml.AliasNode {
				v = v.Alias
			}
			return v, m.Content[i]
		}
	}
	return nil, nil
}

// root returns the top-level node of a document node.
func root(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		return doc.Content[0]
	}
	return doc
}

// CheckCompose applies rule 4 of the image pin check to a Compose file:
// a service without build: names image: name:tag@sha256:<64 hex>; a
// service with build: names its image in ownImageForm and
// builds from a local context. build may only use the keys in
// composeBuildKeys (so x-bake, additional_contexts, dockerfile_inline and
// any new key are reported), and its args may not set BUILDKIT_SYNTAX. A
// URL context, extends and a top-level include are reported: they can
// pull images or sources this check does not see. So is a service's
// pull_policy, with any value (#66 item 9b).
//
// It also returns the Dockerfile of every build with a valid local context
// (relative to the Compose file's directory), so the caller checks it with
// the Dockerfile rules whatever its name.
func CheckCompose(src []byte) ([]Finding, []string, error) {
	docs, err := parseYAML(src)
	if err != nil {
		return nil, nil, err
	}
	var out []Finding
	var dockerfiles []string
	add := func(line int, format string, a ...any) {
		out = append(out, Finding{line, fmt.Sprintf(format, a...)})
	}
	if len(docs) != 1 {
		add(0, "a Compose file must hold exactly one YAML document, found %d", len(docs))
		return out, dockerfiles, nil
	}
	top := root(docs[0])
	if top.Kind != yaml.MappingNode {
		add(top.Line, "the Compose file is not a mapping")
		return out, dockerfiles, nil
	}
	if _, k := mappingValue(top, "include"); k != nil {
		add(k.Line, "include: is not read by this check")
	}
	services, k := mappingValue(top, "services")
	if services == nil {
		return out, dockerfiles, nil
	}
	if services.Kind != yaml.MappingNode {
		add(k.Line, "services: is not a mapping")
		return out, dockerfiles, nil
	}
	for i := 0; i+1 < len(services.Content); i += 2 {
		name, val := services.Content[i], services.Content[i+1]
		if name.Value == "<<" || name.Kind != yaml.ScalarNode {
			add(name.Line, "a merge key or non-scalar key under services: is not read by this check")
			continue
		}
		var svc map[string]any
		if err := val.Decode(&svc); err != nil {
			add(name.Line, "service %s does not decode: %v", name.Value, err)
			continue
		}
		if df := checkService(name.Line, name.Value, svc, add); df != "" {
			dockerfiles = append(dockerfiles, df)
		}
	}
	return out, dockerfiles, nil
}

// checkService applies rule 4 to one service. For a build from a valid
// local context it returns the Dockerfile's path relative to the Compose
// file's directory (Compose resolves `dockerfile` against the context).
func checkService(line int, name string, svc map[string]any, add func(int, string, ...any)) string {
	if _, ok := svc["extends"]; ok {
		add(line, "service %s: extends is not read by this check", name)
	}
	// Any pull_policy, whatever its value (#66 item 9b): a plain `up`
	// without --pull never honours it, and `always` would pull an own
	// image by tag over the verified one.
	if p, ok := svc["pull_policy"]; ok {
		add(line, "service %s: pull_policy (%v) is not allowed: the template is started only with --pull never, and the key could pull an image this check has not verified", name, p)
	}
	image, hasImage := svc["image"]
	imageStr, isStr := image.(string)
	if hasImage && !isStr {
		add(line, "service %s: image is not a string", name)
		return ""
	}
	build, hasBuild := svc["build"]
	if !hasBuild {
		switch {
		case !hasImage:
			add(line, "service %s has neither image nor build", name)
		case !isPinnedImage(imageStr):
			add(line, "service %s: %s", name, unpinnedMsg("image", imageStr))
		}
		return ""
	}
	if !ownImageNameRE.MatchString(ownImageName(imageStr)) {
		add(line, "service %s builds an image; name it exactly %s (or as ${KEEPIA_<NAME>_IMAGE:-<that name>})", name, ownImageForm)
	}
	context, dockerfile := ".", "Dockerfile"
	switch b := build.(type) {
	case string:
		context = b
	case map[string]any:
		if c, ok := b["context"]; ok {
			s, ok := c.(string)
			if !ok {
				add(line, "service %s: build.context is not a string", name)
				return ""
			}
			context = s
		}
		if d, ok := b["dockerfile"]; ok {
			s, ok := d.(string)
			if !ok || !isLocalContext(s) {
				add(line, "service %s: build.dockerfile %v is not a relative path inside the context", name, d)
				return ""
			}
			dockerfile = s
		}
		keys := make([]string, 0, len(b))
		for k := range b {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !composeBuildKeys[k] {
				add(line, "service %s: build.%s is not allowed (allowed: context, dockerfile, args, target, labels); it can change what is built in a way this check does not read", name, k)
			}
		}
		if hasSyntaxArg(b["args"]) {
			add(line, "service %s: build.args.BUILDKIT_SYNTAX overrides the pinned # syntax= directive", name)
		}
	default:
		add(line, "service %s: build is neither a string nor a mapping", name)
		return ""
	}
	if !isLocalContext(context) {
		add(line, "service %s: build context %q is not a local relative path", name, context)
		return ""
	}
	return context + "/" + dockerfile
}

// ownImageOverride is an own image's name behind a variable that can
// replace it as a whole: ${KEEPIA_<NAME>_IMAGE:-<default>}, or
// ${KEEPIA_IMAGE:-<default>}. The CI compose job sets it to the verified
// image ID of the loaded image, so nothing goes by tag after the
// verification (#26; .claude/rules/docker.md). The default is checked as
// the name.
var ownImageOverride = regexp.MustCompile(`^\$\{KEEPIA_(?:[A-Z0-9]+_)?IMAGE:-(.+)\}$`)

// ownImageName is the name rule 4 checks for a service that builds: the
// default of an ownImageOverride, or image itself.
func ownImageName(image string) string {
	if m := ownImageOverride.FindStringSubmatch(image); m != nil {
		return m[1]
	}
	return image
}

// composeBuildKeys are the build keys a Compose service may use. Anything
// else (x-bake, additional_contexts, dockerfile_inline, cache_from, ssh,
// secrets, network, …) is reported: an allowlist fails closed on keys
// Compose or bake add later.
var composeBuildKeys = map[string]bool{
	"context": true, "dockerfile": true, "args": true, "target": true, "labels": true,
}

// hasSyntaxArg reports whether Compose build args (a mapping, or a list of
// KEY=VALUE or KEY) set BUILDKIT_SYNTAX.
func hasSyntaxArg(args any) bool {
	isSyntax := func(k string) bool { return strings.EqualFold(strings.TrimSpace(k), "BUILDKIT_SYNTAX") }
	switch a := args.(type) {
	case map[string]any:
		for k := range a {
			if isSyntax(k) {
				return true
			}
		}
	case []any:
		for _, e := range a {
			s, _ := e.(string)
			k, _, _ := strings.Cut(s, "=")
			if isSyntax(k) {
				return true
			}
		}
	}
	return false
}

// isLocalContext reports whether a build context is a relative path inside
// the repository: no URL, no git remote, no variable, not absolute, no "..".
func isLocalContext(c string) bool {
	if c == "" || strings.ContainsAny(c, "$#:@\\") || strings.HasPrefix(c, "/") {
		return false
	}
	for _, part := range strings.Split(c, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}
