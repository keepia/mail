package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// registryPrefix is how an own image is named in the Compose file: under
// the registry variable, so the release bundle can pin it (part 4).
const registryPrefix = "${KEEPIA_REGISTRY"

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
// service with build: names its image under ${KEEPIA_REGISTRY...} and
// builds from a local context. A URL context, build.additional_contexts,
// build.dockerfile_inline, extends and a top-level include are reported:
// they can pull images or sources this check does not see.
func CheckCompose(src []byte) ([]Finding, error) {
	docs, err := parseYAML(src)
	if err != nil {
		return nil, err
	}
	var out []Finding
	add := func(line int, format string, a ...any) {
		out = append(out, Finding{line, fmt.Sprintf(format, a...)})
	}
	if len(docs) != 1 {
		add(0, "a Compose file must hold exactly one YAML document, found %d", len(docs))
		return out, nil
	}
	top := root(docs[0])
	if top.Kind != yaml.MappingNode {
		add(top.Line, "the Compose file is not a mapping")
		return out, nil
	}
	if _, k := mappingValue(top, "include"); k != nil {
		add(k.Line, "include: is not read by this check")
	}
	services, k := mappingValue(top, "services")
	if services == nil {
		return out, nil
	}
	if services.Kind != yaml.MappingNode {
		add(k.Line, "services: is not a mapping")
		return out, nil
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
		checkService(name.Line, name.Value, svc, add)
	}
	return out, nil
}

func checkService(line int, name string, svc map[string]any, add func(int, string, ...any)) {
	if _, ok := svc["extends"]; ok {
		add(line, "service %s: extends is not read by this check", name)
	}
	image, hasImage := svc["image"]
	imageStr, isStr := image.(string)
	if hasImage && !isStr {
		add(line, "service %s: image is not a string", name)
		return
	}
	build, hasBuild := svc["build"]
	if !hasBuild {
		switch {
		case !hasImage:
			add(line, "service %s has neither image nor build", name)
		case !isPinnedImage(imageStr):
			add(line, "service %s: %s", name, unpinnedMsg("image", imageStr))
		}
		return
	}
	if !strings.HasPrefix(imageStr, registryPrefix) {
		add(line, "service %s builds an image; name it under %s...}", name, registryPrefix)
	}
	context := "."
	switch b := build.(type) {
	case string:
		context = b
	case map[string]any:
		if c, ok := b["context"]; ok {
			s, ok := c.(string)
			if !ok {
				add(line, "service %s: build.context is not a string", name)
				return
			}
			context = s
		}
		for _, k := range []string{"additional_contexts", "dockerfile_inline"} {
			if _, ok := b[k]; ok {
				add(line, "service %s: build.%s is not read by this check", name, k)
			}
		}
	default:
		add(line, "service %s: build is neither a string nor a mapping", name)
		return
	}
	if !isLocalContext(context) {
		add(line, "service %s: build context %q is not a local relative path", name, context)
	}
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
