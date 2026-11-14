package gate

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestMain runs U21 after the package's tests: no captured gate log may
// hold key material, a PEM block, the DER of any key, certificate or list
// the tests made (in base64), a private scalar (hex or base64), or any
// byte of a file the gate refused (its marker).
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		registry.mu.Lock()
		logs := make([]string, len(registry.logs))
		for i, l := range registry.logs {
			logs[i] = l.String()
		}
		ders, keys, markers := registry.ders, registry.keys, registry.markers
		registry.mu.Unlock()
		if err := scanLogs(strings.Join(logs, "\n"), ders, keys, markers); err != nil {
			fmt.Fprintf(os.Stderr, "U21: %v\n", err)
			code = 1
		} else {
			fmt.Fprintf(os.Stderr, "U21: %d logs (%d bytes) hold none of %d DER blobs, %d keys, %d markers\n",
				len(logs), len(strings.Join(logs, "\n")), len(ders), len(keys), len(markers))
		}
	}
	os.Exit(code)
}

// b64run is a run of base64 (standard or URL) characters long enough to
// carry 18 bytes.
var b64run = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}`)

// scanLogs is U21's check.
func scanLogs(log string, ders [][]byte, keys []*ecdsa.PrivateKey, markers []string) error {
	for _, s := range []string{"PRIVATE KEY", "BEGIN", "END CERTIFICATE", "X509 CRL"} {
		if strings.Contains(log, s) {
			return fmt.Errorf("the logs hold %q", s)
		}
	}
	for _, m := range markers {
		if strings.Contains(log, m) {
			return errors.New("the logs quote a refused file")
		}
	}
	// Every encoding of every DER at every byte alignment, so a base64
	// run in the log that is part of one is found whatever its offset.
	var enc strings.Builder
	for _, d := range ders {
		for k := 0; k < 3 && k < len(d); k++ {
			enc.WriteString(base64.StdEncoding.EncodeToString(d[k:]))
			enc.WriteByte('\n')
			enc.WriteString(base64.RawURLEncoding.EncodeToString(d[k:]))
			enc.WriteByte('\n')
		}
	}
	for _, k := range keys {
		d, err := k.Bytes()
		if err != nil {
			return err
		}
		h := hex.EncodeToString(d)
		if strings.Contains(strings.ToLower(log), h[:32]) || strings.Contains(strings.ToLower(log), h[32:]) {
			return errors.New("the logs hold a private scalar in hex")
		}
		for i := 0; i < 3; i++ {
			enc.WriteString(base64.StdEncoding.EncodeToString(d[i:]))
			enc.WriteByte('\n')
		}
	}
	all := enc.String()
	for _, run := range b64run.FindAllString(log, -1) {
		for j := 0; j < 4 && j+24 <= len(run); j++ {
			if strings.Contains(all, run[j:j+24]) {
				return fmt.Errorf("the logs hold base64 of key, certificate or list material (%d characters)", len(run))
			}
		}
	}
	return nil
}

// U21 (V7): the scan finds a key's PEM, its DER in base64 at any offset,
// a certificate's DER, a scalar in hex, and a refused file's marker; it
// passes a clean log.
func TestLogScanFindsMaterial(t *testing.T) {
	k := newKey(t)
	f := newFixture(t, RoleStore, newFakeClock().Now())
	der := mustPKCS8(t, k)
	keys := []*ecdsa.PrivateKey{k}
	ders := [][]byte{der, f.gate.cert.Raw}
	clean := `time=2026-11-14T12:00:00Z level=INFO msg="applied generation 3" serial=` + f.gate.cert.SerialNumber.Text(16)
	if err := scanLogs(clean, ders, keys, []string{"REFUSEDMARKERx"}); err != nil {
		t.Fatalf("a clean log: %v", err)
	}
	scalar, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b64 := base64.StdEncoding.EncodeToString(der[1:])
	dirty := map[string]string{
		"PEM":            clean + " key=" + strings.ReplaceAll(pemKey, "\n", `\n`),
		"base64 offset":  clean + ` key="` + b64[8:60] + `"`,
		"certificate":    clean + " cert=" + base64.StdEncoding.EncodeToString(f.gate.cert.Raw),
		"hex scalar":     clean + " d=" + hex.EncodeToString(scalar),
		"refused marker": clean + ` content="REFUSEDMARKERx"`,
	}
	for name, log := range dirty {
		if err := scanLogs(log, ders, keys, []string{"REFUSEDMARKERx"}); err == nil {
			t.Errorf("%s: the scan passed", name)
		}
	}
}

func mustPKCS8(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
