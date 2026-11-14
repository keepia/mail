package gatebundle

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/keepia/mail/internal/pki"
)

// Bundle is a gate's TLS material (X108-2).
type Bundle struct {
	// Chain is what the gate presents: its leaf, then the service anchor.
	Chain []*x509.Certificate
	// Key is the leaf's private key (ECDSA P-256).
	Key crypto.Signer
	// Anchors are the anchors the gate's listeners trust, and the service
	// anchor of its own leaf: agent and service for the control gate,
	// store-client and service for a store gate.
	Anchors map[pki.AnchorName]*x509.Certificate
	// Lists are each anchor's revocation list as signed (DER). Read checks
	// only their signature and issuer: the holder verifies them with
	// pki.VerifyCRL against the list it holds (X108-1).
	Lists map[pki.AnchorName][]byte
}

// Leaf is Chain[0].
func (b *Bundle) Leaf() *x509.Certificate { return b.Chain[0] }

// The PEM form of bundle.pem, in this order: the leaf (CERTIFICATE), the
// service anchor as presented (CERTIFICATE), the leaf's key (PRIVATE KEY,
// PKCS#8), then for each anchor, sorted by name, its certificate and its
// list (CERTIFICATE and X509 CRL), each with the header Keepia-Anchor.
const (
	pemCertificate = "CERTIFICATE"
	pemKey         = "PRIVATE KEY"
	pemCRL         = "X509 CRL"
	headerAnchor   = "Keepia-Anchor"
)

// encode checks b and returns bundle.pem's content.
func encode(b *Bundle) ([]byte, error) {
	if err := check(b); err != nil {
		return nil, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(b.Key)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	add := func(typ string, der []byte, headers map[string]string) {
		_ = pem.Encode(&buf, &pem.Block{Type: typ, Headers: headers, Bytes: der})
	}
	add(pemCertificate, b.Chain[0].Raw, nil)
	add(pemCertificate, b.Chain[1].Raw, nil)
	add(pemKey, key, nil)
	for _, name := range sortedNames(b.Anchors) {
		h := map[string]string{headerAnchor: string(name)}
		add(pemCertificate, b.Anchors[name].Raw, h)
		add(pemCRL, b.Lists[name], h)
	}
	return buf.Bytes(), nil
}

func sortedNames(m map[pki.AnchorName]*x509.Certificate) []pki.AnchorName {
	names := make([]pki.AnchorName, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// check is what Read accepts (X108-1, X108-3): the key belongs to the
// leaf; the leaf chains to the bundle's service anchor, which is the
// presented chain's second certificate, with serverAuth and exactly one
// DNS SAN (any name: callers check it); every anchor is a known one and
// has exactly one list, signed by it with its subject as the issuer. It
// checks neither the leaf's validity nor the lists' nextUpdate: the
// holder does, with its own clock and its held lists.
func check(b *Bundle) error {
	if len(b.Chain) != 2 || b.Chain[0] == nil || b.Chain[1] == nil {
		return fmt.Errorf("%w: the chain must be the leaf and the service anchor", ErrRefused)
	}
	leaf := b.Chain[0]
	service := b.Anchors[pki.AnchorService]
	if service == nil {
		return fmt.Errorf("%w: no service anchor", ErrRefused)
	}
	if !bytes.Equal(b.Chain[1].Raw, service.Raw) {
		return fmt.Errorf("%w: the presented chain does not end in the bundle's service anchor", ErrRefused)
	}
	if len(leaf.DNSNames) != 1 {
		return fmt.Errorf("%w: the leaf must have exactly one DNS name", ErrRefused)
	}
	// The chain is checked at the leaf's NotBefore, so its structure is
	// checked and its validity left to the holder.
	if _, err := pki.VerifyServerChain(b.Chain[:1], service, leaf.DNSNames[0], leaf.NotBefore); err != nil {
		return fmt.Errorf("%w: the leaf: %w", ErrRefused, err)
	}
	pub, ok := b.Key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !pub.Equal(leaf.PublicKey) {
		return fmt.Errorf("%w: the key does not belong to the leaf", ErrRefused)
	}
	if len(b.Lists) != len(b.Anchors) {
		return fmt.Errorf("%w: every anchor needs exactly one list", ErrRefused)
	}
	for name, a := range b.Anchors {
		if !slices.Contains(pki.Anchors, name) || a == nil {
			return fmt.Errorf("%w: unknown anchor %q", ErrRefused, name)
		}
		der, ok := b.Lists[name]
		if !ok {
			return fmt.Errorf("%w: no list for the anchor %s", ErrRefused, name)
		}
		rl, err := x509.ParseRevocationList(der)
		if err != nil {
			return fmt.Errorf("%w: the list of %s does not parse", ErrRefused, name)
		}
		if !bytes.Equal(rl.RawIssuer, a.RawSubject) || rl.CheckSignatureFrom(a) != nil {
			return fmt.Errorf("%w: the list of %s is not signed by its anchor", ErrRefused, name)
		}
	}
	return nil
}

// Read reads and checks dir/bundle.pem (CD35 with C12 and X108-1 to
// X108-3). The file is opened with O_NOFOLLOW|O_NONBLOCK, must be a
// regular file by fstat and at most 64 KiB, and must be exactly the PEM
// form Write writes. It returns the whole set or an error, never part of
// it; a missing file wraps fs.ErrNotExist, a refused one ErrRefused, and
// no error quotes the file.
func Read(dir string) (*Bundle, error) {
	path := filepath.Join(dir, BundleFile)
	raw, err := readFile(path, maxBundle)
	if err != nil {
		return nil, err
	}
	bad := func(what string) error { return fmt.Errorf("%w: %s: %s", ErrRefused, path, what) }
	var blocks []*pem.Block
	rest := raw
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, bad("data outside the PEM blocks")
	}
	if len(blocks) < 5 || (len(blocks)-3)%2 != 0 {
		return nil, bad("not a gate bundle")
	}
	b := &Bundle{Anchors: map[pki.AnchorName]*x509.Certificate{}, Lists: map[pki.AnchorName][]byte{}}
	for i := range 2 {
		if blocks[i].Type != pemCertificate || len(blocks[i].Headers) != 0 {
			return nil, bad("the chain must come first")
		}
		c, err := x509.ParseCertificate(blocks[i].Bytes)
		if err != nil {
			return nil, bad("a certificate of the chain does not parse")
		}
		b.Chain = append(b.Chain, c)
	}
	if blocks[2].Type != pemKey || len(blocks[2].Headers) != 0 {
		return nil, bad("the key must follow the chain")
	}
	k, err := x509.ParsePKCS8PrivateKey(blocks[2].Bytes)
	if err != nil {
		return nil, bad("the key does not parse")
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, bad("the key cannot sign")
	}
	b.Key = signer
	for i := 3; i < len(blocks); i += 2 {
		cb, lb := blocks[i], blocks[i+1]
		name := pki.AnchorName(cb.Headers[headerAnchor])
		if cb.Type != pemCertificate || lb.Type != pemCRL || len(cb.Headers) != 1 || len(lb.Headers) != 1 ||
			lb.Headers[headerAnchor] != string(name) {
			return nil, bad("each anchor must be a certificate and its list, with the same Keepia-Anchor")
		}
		if _, dup := b.Anchors[name]; dup {
			return nil, bad("an anchor appears twice")
		}
		c, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			return nil, bad("an anchor does not parse")
		}
		b.Anchors[name] = c
		b.Lists[name] = lb.Bytes
	}
	if err := check(b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// Test seams (export_test.go): run between the steps of Write.
var (
	beforeBundleRename     func()
	beforeGenerationRename func()
)

// Write writes b into dir (CD34 with C10) and returns the generation it
// wrote:
//
//  0. remove a leftover bundle.pem.tmp and generation.tmp (unlink, which
//     never follows a link): serve is the only writer, so they are what
//     a crash left behind;
//  1. bundle.pem.tmp with O_CREAT|O_EXCL|O_NOFOLLOW, mode 0400, fsync;
//  2. rename it to bundle.pem;
//  3. generation.tmp the same way with mode 0444, then rename it to
//     generation;
//  4. fsync the directory.
//
// The generation is the file's value + 1. On a new directory (neither
// file) it is 1; when generation is missing or invalid next to a bundle,
// it is the current Unix time in seconds (N10), which is far above any
// counter, so a reader that holds a higher value than the file still sees
// a different one. A reader sees the old complete bundle or the new one,
// never a mix.
func Write(dir string, b *Bundle) (uint64, error) {
	content, err := encode(b)
	if err != nil {
		return 0, err
	}
	gen, err := nextGeneration(dir)
	if err != nil {
		return 0, err
	}
	bundlePath := filepath.Join(dir, BundleFile)
	genPath := filepath.Join(dir, GenerationFile)
	for _, p := range []string{bundlePath + ".tmp", genPath + ".tmp"} {
		if err := syscall.Unlink(p); err != nil && !errors.Is(err, syscall.ENOENT) {
			return 0, fmt.Errorf("remove %s: %w", p, err)
		}
	}
	if err := writeTemp(bundlePath+".tmp", content, 0o400); err != nil {
		return 0, err
	}
	if beforeBundleRename != nil {
		beforeBundleRename()
	}
	if err := os.Rename(bundlePath+".tmp", bundlePath); err != nil {
		return 0, err
	}
	if err := writeTemp(genPath+".tmp", []byte(strconv.FormatUint(gen, 10)+"\n"), 0o444); err != nil {
		return 0, err
	}
	if beforeGenerationRename != nil {
		beforeGenerationRename()
	}
	if err := os.Rename(genPath+".tmp", genPath); err != nil {
		return 0, err
	}
	return gen, syncDir(dir)
}

// maxGenerationValue is the largest generation of 19 digits.
const maxGenerationValue = 9_999_999_999_999_999_999

func nextGeneration(dir string) (uint64, error) {
	cur, err := ReadGeneration(dir)
	switch {
	case err == nil:
		if cur >= maxGenerationValue {
			return 0, fmt.Errorf("%s: the generation cannot grow past %d", filepath.Join(dir, GenerationFile), uint64(maxGenerationValue))
		}
		return cur + 1, nil
	case errors.Is(err, fs.ErrNotExist):
		if _, err := os.Lstat(filepath.Join(dir, BundleFile)); errors.Is(err, fs.ErrNotExist) {
			return 1, nil
		}
	case !errors.Is(err, ErrRefused):
		return 0, err
	}
	return uint64(max(time.Now().Unix(), 1)), nil
}

// writeTemp creates path with O_EXCL|O_NOFOLLOW and mode, writes data
// and syncs it.
func writeTemp(path string, data []byte, mode uint32) (err error) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("close %s: %w", path, cerr)
		}
	}()
	// The umask may have taken bits off mode; make it exact.
	if err := f.Chmod(os.FileMode(mode)); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	return nil
}

func syncDir(dir string) error {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the directory %s: %w", dir, err)
	}
	d := os.NewFile(uintptr(fd), dir)
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync the directory %s: %w", dir, err)
	}
	return nil
}
