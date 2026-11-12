package main

import (
	"strings"
	"testing"
)

// TestReferencedBinary: a file that is not text is not read as a script
// (#50 review A, finding 2e: a built golangci-lint gave 64 MB of "it
// runs …"), and running one is a problem the check reports.
func TestReferencedBinary(t *testing.T) {
	root := t.TempDir()
	write(t, root, "bin/tool", "\x7fELF\x00\x00\x00 ./x.sh /tmp/y $Z\n")
	texts, problems := referencedTexts(root, "ls -l bin/tool", "", true)
	for _, tx := range texts {
		if strings.Contains(tx.text, "\x00") {
			t.Errorf("a binary was read as text: %s", tx.path)
		}
	}
	if len(problems) > 0 {
		t.Errorf("naming a binary: problems %q, want none", problems)
	}
	_, problems = referencedTexts(root, "./bin/tool", "", true)
	if len(problems) != 1 || !strings.Contains(problems[0], "a binary the check cannot read") {
		t.Errorf("running a binary: problems %q, want one that names the binary", problems)
	}
}
