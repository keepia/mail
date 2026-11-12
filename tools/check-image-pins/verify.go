package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Verify mode (`-verify-built`, CI): the images a job tests and uploads
// are the ones the checked build produced. It reads docker/bake-action's
// metadata output (BAKE_METADATA) and compares, for every image name a
// target built, the local image ID with the digest the build reported.
// Anything that replaced or re-tagged the image after the build (another
// build, a docker tag, a docker load) makes the IDs differ, whatever
// produced it (review B delta 2, D2).
//
// The local ID is the manifest digest with Docker's containerd image
// store, and the config digest with the classic store; the metadata has
// both (containerimage.digest, containerimage.config.digest).

type builtImage struct {
	Name         string `json:"image.name"`
	Digest       string `json:"containerimage.digest"`
	ConfigDigest string `json:"containerimage.config.digest"`
}

// verifyBuilt checks metadata against inspect (image name → local ID).
func verifyBuilt(meta []byte, inspect func(string) (string, error)) ([]string, int) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(meta, &top); err != nil {
		return []string{fmt.Sprintf("the build metadata does not parse: %v", err)}, 0
	}
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var findings []string
	checked := 0
	for _, target := range keys {
		raw := bytes.TrimSpace(top[target])
		if len(raw) == 0 || raw[0] != '{' {
			continue // e.g. buildx.build.warnings
		}
		var b builtImage
		if err := json.Unmarshal(raw, &b); err != nil {
			findings = append(findings, fmt.Sprintf("target %q: metadata does not parse: %v", target, err))
			continue
		}
		if b.Name == "" || (b.Digest == "" && b.ConfigDigest == "") {
			findings = append(findings, fmt.Sprintf("target %q: the metadata names no image or digest", target))
			continue
		}
		for _, name := range strings.Split(b.Name, ",") {
			name = strings.TrimSpace(name)
			checked++
			id, err := inspect(name)
			switch {
			case err != nil:
				findings = append(findings, fmt.Sprintf("target %q: image %s is not in the local store: %v", target, name, err))
			case id != b.Digest && id != b.ConfigDigest:
				findings = append(findings, fmt.Sprintf("target %q: image %s is %s, but the checked build produced %s (config %s): it was replaced after the build", target, name, id, b.Digest, b.ConfigDigest))
			}
		}
	}
	if checked == 0 && len(findings) == 0 {
		findings = append(findings, "the build metadata names no image")
	}
	return findings, checked
}

// dockerImageID returns the local image ID of name.
func dockerImageID(name string) (string, error) {
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", "--", name).Output() //nolint:gosec // name comes from the build's own metadata
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// runVerify is verify mode.
func runVerify(stdout io.Writer) int {
	meta := os.Getenv("BAKE_METADATA")
	r := &report{out: stdout}
	if strings.TrimSpace(meta) == "" {
		r.add("BAKE_METADATA", 0, "empty: set it to the bake-action step's metadata output")
		fmt.Fprintln(stdout, "check-image-pins: the built image cannot be verified.")
		return 1
	}
	findings, n := verifyBuilt([]byte(meta), dockerImageID)
	for _, f := range findings {
		r.add("BAKE_METADATA", 0, f)
	}
	if r.bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s): the local images are not the checked build.\n", r.bad)
		return 1
	}
	fmt.Fprintf(stdout, "check-image-pins: %d image name(s) are the checked build's output.\n", n)
	return 0
}
