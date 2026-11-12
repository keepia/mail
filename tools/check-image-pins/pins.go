package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Finding is one problem at a line of a file. Line 0 stands for the whole
// file (it does not parse).
type Finding struct {
	Line int
	Msg  string
}

func (f Finding) String() string {
	return fmt.Sprintf("%d: %s", f.Line, f.Msg)
}

// imageName is a reference name without tag or digest: an optional
// registry host (with a dot or a port, or localhost) and one or more
// lowercase path components (the distribution reference grammar).
const imageName = `(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?::[0-9]+)?|localhost(?::[0-9]+)?|[a-z0-9]+:[0-9]+)/)?` +
	`[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*`

const digest = `@sha256:[0-9a-f]{64}`

var (
	// pinnedImage is name:tag@sha256:<64 hex>. The tag stays for the
	// reader and Dependabot; the digest decides what is pulled.
	pinnedImage = regexp.MustCompile(`^` + imageName + `:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` + digest + `$`)
	// pinnedSyntax is a # syntax= frontend: name:X.Y.Z@sha256:<64 hex>.
	pinnedSyntax = regexp.MustCompile(`^` + imageName + `:[0-9]+\.[0-9]+\.[0-9]+` + digest + `$`)
	// sha256Checksum is the only checksum form ADD may carry.
	sha256Checksum = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// isPinnedImage reports whether ref is name:tag@sha256:<64 hex>.
func isPinnedImage(ref string) bool {
	return pinnedImage.MatchString(ref)
}

// unpinnedMsg explains why ref is not accepted as an image reference.
func unpinnedMsg(what, ref string) string {
	if strings.Contains(ref, "$") {
		return fmt.Sprintf("%s %q uses a variable; name the image as name:tag@sha256:<64 hex>", what, ref)
	}
	return fmt.Sprintf("%s %q is not pinned as name:tag@sha256:<64 hex>", what, ref)
}
