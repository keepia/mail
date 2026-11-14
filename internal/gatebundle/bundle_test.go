package gatebundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/pki/pkitest"
	"github.com/keepia/mail/internal/testwait"
)

var testNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// material is a control gate bundle issued at now from keys, with lists
// issued at listsAt.
func material(t *testing.T, keys pkitest.Keys, leaf pki.Leaf, now, listsAt time.Time) *Bundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := keys.Anchor(pki.AnchorService)
	cert, err := pki.Issue(service, leaf, key.Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	b := &Bundle{
		Chain:   []*x509.Certificate{cert, service.Cert},
		Key:     key,
		Anchors: map[pki.AnchorName]*x509.Certificate{},
		Lists:   map[pki.AnchorName][]byte{},
	}
	for _, name := range []pki.AnchorName{pki.AnchorAgent, pki.AnchorService} {
		der, err := pki.CreateCRL(keys.Anchor(name), 1, nil, listsAt)
		if err != nil {
			t.Fatal(err)
		}
		b.Anchors[name] = keys.Anchor(name).Cert
		b.Lists[name] = der
	}
	return b
}

func controlBundle(t *testing.T, keys pkitest.Keys) *Bundle {
	t.Helper()
	return material(t, keys, pki.ControlGateLeaf(), testNow, testNow)
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

// A written bundle reads back whole; the files have their modes, and the
// generation starts at 1 on a new directory and then rises by one.
func TestWriteRead(t *testing.T) {
	keys := pkitest.NewKeys(t, testNow)
	dir := t.TempDir()
	b := controlBundle(t, keys)
	gen, err := Write(dir, b)
	if err != nil || gen != 1 {
		t.Fatalf("first write: generation %d, %v", gen, err)
	}
	if m := mode(t, filepath.Join(dir, BundleFile)); m != 0o400 {
		t.Errorf("bundle.pem mode %v, want 0400", m)
	}
	if m := mode(t, filepath.Join(dir, GenerationFile)); m != 0o444 {
		t.Errorf("generation mode %v, want 0444", m)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Leaf().Equal(b.Leaf()) || !got.Chain[1].Equal(b.Chain[1]) || len(got.Anchors) != 2 ||
		!bytes.Equal(got.Lists[pki.AnchorAgent], b.Lists[pki.AnchorAgent]) || !got.Anchors[pki.AnchorService].Equal(b.Anchors[pki.AnchorService]) {
		t.Error("the bundle does not read back as written")
	}
	if !got.Key.Public().(*ecdsa.PublicKey).Equal(b.Key.Public()) {
		t.Error("the key does not read back")
	}
	if g, err := ReadGeneration(dir); err != nil || g != 1 {
		t.Errorf("generation %d, %v", g, err)
	}
	if gen, err := Write(dir, b); err != nil || gen != 2 {
		t.Errorf("second write: generation %d, %v", gen, err)
	}
}

// X108-1, X108-3: Read accepts a bundle whose lists have passed
// nextUpdate (the holder refuses them with pki.VerifyCRL), and a leaf for
// any single DNS name.
func TestReadLeavesTimeAndNameToTheHolder(t *testing.T) {
	keys := pkitest.NewKeys(t, testNow.Add(-30*24*time.Hour))
	dir := t.TempDir()
	leaf, err := pki.GateLeaf(pki.RoleStore, "s1", 7)
	if err != nil {
		t.Fatal(err)
	}
	b := material(t, keys, leaf, testNow, testNow.Add(-8*24*time.Hour))
	if _, err := Write(dir, b); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatalf("a bundle with expired lists: %v", err)
	}
	if got.Leaf().DNSNames[0] != "s1.store.keepia.internal" {
		t.Errorf("leaf %v", got.Leaf().DNSNames)
	}
	if _, err := pki.VerifyCRL(got.Lists[pki.AnchorService], got.Anchors[pki.AnchorService], nil, testNow); !errors.Is(err, pki.ErrCRLExpired) {
		t.Errorf("the holder's check of the expired list: %v, want ErrCRLExpired", err)
	}
}

// Read and Write refuse a set that does not fit together.
func TestBundleRefusesMismatch(t *testing.T) {
	keys := pkitest.NewKeys(t, testNow)
	other := pkitest.NewKeys(t, testNow)
	cases := map[string]func(b *Bundle){
		"key of another leaf": func(b *Bundle) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			b.Key = k
		},
		"chain of another service anchor": func(b *Bundle) { b.Chain[1] = other.Anchor(pki.AnchorService).Cert },
		"list of another anchor": func(b *Bundle) {
			der, _ := pki.CreateCRL(other.Anchor(pki.AnchorAgent), 1, nil, testNow)
			b.Lists[pki.AnchorAgent] = der
		},
		"missing list": func(b *Bundle) { delete(b.Lists, pki.AnchorAgent) },
		"no service":   func(b *Bundle) { delete(b.Anchors, pki.AnchorService); delete(b.Lists, pki.AnchorService) },
		"leaf of agent anchor": func(b *Bundle) {
			agent := keys.Anchor(pki.AnchorAgent)
			l, _ := pki.ClientLeaf(pki.PurposeAgent, 3)
			c, err := pki.Issue(agent, l, b.Key.Public(), testNow)
			if err != nil {
				t.Fatal(err)
			}
			b.Chain[0] = c
		},
	}
	for name, mutate := range cases {
		b := controlBundle(t, keys)
		mutate(b)
		if _, err := Write(t.TempDir(), b); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: Write %v, want ErrRefused", name, err)
		}
	}
	// A file that Write never writes: the blocks reordered.
	dir := t.TempDir()
	if _, err := Write(dir, controlBundle(t, keys)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Index(string(raw), "-----BEGIN PRIVATE KEY")
	swapped := string(raw[first:]) + string(raw[:first])
	replace(t, dir, swapped)
	if _, err := Read(dir); !errors.Is(err, ErrRefused) || strings.Contains(err.Error(), "MII") {
		t.Errorf("reordered blocks: %v", err)
	}
}

// replace puts content in place of dir/bundle.pem.
func replace(t *testing.T, dir, content string) {
	t.Helper()
	p := filepath.Join(dir, BundleFile)
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o400); err != nil {
		t.Fatal(err)
	}
}

// bounded runs f in a goroutine and fails if it does not return within
// testwait.Limit: a hang guard for the FIFO cases.
func bounded(t *testing.T, what string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(testwait.Limit(t)):
		t.Fatalf("%s did not return", what)
		return nil
	}
}

// C12: bundle.pem is refused as a link, a FIFO (without a hang) and when
// larger than 64 KiB, and the error never quotes it.
func TestReadRefusesUnsafeFiles(t *testing.T) {
	keys := pkitest.NewKeys(t, testNow)
	good := t.TempDir()
	if _, err := Write(good, controlBundle(t, keys)); err != nil {
		t.Fatal(err)
	}
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(good, BundleFile), filepath.Join(link, BundleFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("link: %v", err)
	}
	fifo := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(fifo, BundleFile), 0o600); err != nil {
		t.Fatal(err)
	}
	err := bounded(t, "Read of a FIFO", func() error { _, err := Read(fifo); return err })
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("FIFO: %v", err)
	}
	big := t.TempDir()
	secret := "SECRETCONTENT"
	replace(t, big, strings.Repeat(secret, maxBundle/len(secret)+1))
	if _, err := Read(big); !errors.Is(err, ErrRefused) || strings.Contains(err.Error(), secret) {
		t.Errorf("oversized: %v", err)
	}
	junk := t.TempDir()
	replace(t, junk, secret)
	if _, err := Read(junk); !errors.Is(err, ErrRefused) || strings.Contains(err.Error(), secret) {
		t.Errorf("not PEM: %v", err)
	}
	if _, err := Read(t.TempDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v, want fs.ErrNotExist", err)
	}
}

// K5: ReadGeneration refuses a link, a FIFO (without a hang), 07, 12a, 20
// digits and an empty file, without quoting them, and accepts CD35's form.
func TestReadGeneration(t *testing.T) {
	write := func(content string) string {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, GenerationFile), []byte(content), 0o444); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	for _, bad := range []string{"07", "12a", "12345678901234567890", "", "1\n\n", " 1", "-1", "1\r\n"} {
		_, err := ReadGeneration(write(bad))
		// Short values also occur in the fixed message ("of 1 to 19").
		if !errors.Is(err, ErrRefused) || (len(bad) >= 3 && strings.Contains(err.Error(), bad)) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for content, want := range map[string]uint64{"0": 0, "1\n": 1, "9999999999999999999": 9999999999999999999} {
		if got, err := ReadGeneration(write(content)); err != nil || got != want {
			t.Errorf("%q: %d, %v", content, got, err)
		}
	}
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(write("5"), GenerationFile), filepath.Join(link, GenerationFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGeneration(link); !errors.Is(err, ErrRefused) {
		t.Errorf("link: %v", err)
	}
	fifo := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(fifo, GenerationFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bounded(t, "ReadGeneration of a FIFO", func() error { _, err := ReadGeneration(fifo); return err }); !errors.Is(err, ErrRefused) {
		t.Errorf("FIFO: %v", err)
	}
	if _, err := ReadGeneration(t.TempDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

// K5: Write never writes a generation that is not greater than the
// file's, and continues above any counter when the file is invalid or
// missing next to a bundle (N10).
func TestWriteGenerationOnlyRises(t *testing.T) {
	keys := pkitest.NewKeys(t, testNow)
	b := controlBundle(t, keys)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, GenerationFile), []byte("41\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if gen, err := Write(dir, b); err != nil || gen != 42 {
		t.Errorf("after 41: %d, %v", gen, err)
	}
	if err := os.Remove(filepath.Join(dir, GenerationFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, GenerationFile), []byte("4x"), 0o444); err != nil {
		t.Fatal(err)
	}
	floor := uint64(time.Now().Unix())
	if gen, err := Write(dir, b); err != nil || gen < floor {
		t.Errorf("after an invalid file: %d, %v, want at least %d", gen, err, floor)
	}
	if err := os.Remove(filepath.Join(dir, GenerationFile)); err != nil {
		t.Fatal(err)
	}
	if gen, err := Write(dir, b); err != nil || gen < floor {
		t.Errorf("generation missing next to a bundle: %d, %v, want at least %d", gen, err, floor)
	}
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, GenerationFile), []byte("9999999999999999999"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(full, b); err == nil {
		t.Error("a write past 19 digits succeeded")
	}
}

// C10: a leftover bundle.pem.tmp and generation.tmp, also as links, do
// not stop the writer, and a link's target is not touched.
func TestWriteRemovesStaleTemporaries(t *testing.T) {
	keys := pkitest.NewKeys(t, testNow)
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BundleFile+".tmp"), []byte("partial"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, GenerationFile+".tmp")); err != nil {
		t.Fatal(err)
	}
	if gen, err := Write(dir, controlBundle(t, keys)); err != nil || gen != 1 {
		t.Fatalf("write over stale temporaries: %d, %v", gen, err)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "keep" {
		t.Errorf("the link's target: %q, %v", b, err)
	}
	if _, err := Read(dir); err != nil {
		t.Error(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Errorf("directory holds %d entries, want bundle.pem and generation", len(ents))
	}
}

// K4: while a new bundle is being written, a concurrent Read sees the old
// complete bundle, and the generation moves only after bundle.pem.
func TestWriteIsAtomic(t *testing.T) {
	keys := pkitest.NewKeys(t, testNow)
	dir := t.TempDir()
	old := controlBundle(t, keys)
	if _, err := Write(dir, old); err != nil {
		t.Fatal(err)
	}
	next := controlBundle(t, keys)
	var sawBundle, sawGen bool
	beforeBundleRename = func() {
		got, err := Read(dir)
		sawBundle = err == nil && got.Leaf().Equal(old.Leaf())
	}
	beforeGenerationRename = func() {
		got, err := Read(dir)
		g, gerr := ReadGeneration(dir)
		sawGen = err == nil && got.Leaf().Equal(next.Leaf()) && gerr == nil && g == 1
	}
	t.Cleanup(func() { beforeBundleRename, beforeGenerationRename = nil, nil })
	if gen, err := Write(dir, next); err != nil || gen != 2 {
		t.Fatalf("write: %d, %v", gen, err)
	}
	if !sawBundle {
		t.Error("a Read during the write did not see the old complete bundle")
	}
	if !sawGen {
		t.Error("the generation moved before bundle.pem was in place")
	}
}
