package join_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/join"
	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/pki/pkitest"
	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

type env struct {
	st   *store.Store
	obs  *pgx.Conn
	keys pkitest.Keys
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	url := storetest.NewUnmigrated(t)
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	obs, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = obs.Close(ctx) })
	e := &env{st: st, obs: obs, keys: pkitest.NewKeys(t, now.Add(-time.Hour))}
	if err := pki.Reissue(ctx, st, e.keys, now); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) service() *x509.Certificate { return e.keys.Anchor(pki.AnchorService).Cert }

func (e *env) add(t *testing.T, name string, roles ...string) join.Token {
	t.Helper()
	tok, err := join.AddServer(context.Background(), e.st, e.service(), name, roles, join.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *env) redeem(ctx context.Context, t *testing.T, tok join.Token, at time.Time) (*join.Response, error) {
	t.Helper()
	csr, _ := pkitest.CSR(t)
	return join.Redeem(ctx, e.st, e.keys, tok, csr, at)
}

func (e *env) scalar(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := e.obs.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func refusedFor(t *testing.T, what string, err, reason error) {
	t.Helper()
	if !errors.Is(err, join.ErrRefused) || !errors.Is(err, reason) {
		t.Errorf("%s: %v, want a refusal for %v", what, err, reason)
	}
}

// The token's form (CD20), and J9: every malformed token gets one fixed
// error.
func TestTokenFormat(t *testing.T) {
	var pin [32]byte
	pin[0] = 7
	e := pkitest.NewKeys(t, now)
	tok, err := join.RandomToken(pin)
	if err != nil {
		t.Fatal(err)
	}
	s := tok.String()
	if !strings.HasPrefix(s, join.TokenPrefix) || len(s) != len(join.TokenPrefix)+107 {
		t.Fatalf("token %d characters", len(s))
	}
	back, err := join.ParseToken(s)
	if err != nil || back != tok {
		t.Fatalf("round trip: %v", err)
	}
	if join.Pin(e.Anchor(pki.AnchorService).Cert) == join.Pin(e.Anchor(pki.AnchorAgent).Cert) {
		t.Error("two anchors with one pin")
	}
	body := s[len(join.TokenPrefix):]
	for name, bad := range map[string]string{
		"no prefix":      body,
		"version 2":      "keepia-join-v2." + body,
		"short":          s[:len(s)-1],
		"long":           s + "A",
		"bad base64":     s[:len(s)-1] + "*",
		"padding":        s[:len(s)-1] + "=",
		"standard alpha": strings.Replace(s, s[len(s)-1:], "+", 1),
		"empty":          "",
	} {
		if _, err := join.ParseToken(bad); err != join.ErrMalformedToken { //nolint:errorlint // the one fixed error
			t.Errorf("%s: %v, want exactly ErrMalformedToken", name, err)
		}
	}
}

// L1: names, roles and lifetimes are checked before anything is written;
// --ttl 4m59s and 24h1s are refused, 5m and 24h accepted.
func TestServerSpec(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		roles []string
		ttl   time.Duration
		want  error
	}{
		{"S1", []string{"store"}, time.Hour, join.ErrServerSpec},
		{"s1.x", []string{"store"}, time.Hour, join.ErrServerSpec},
		{"-s1", []string{"store"}, time.Hour, join.ErrServerSpec},
		{strings.Repeat("s", 64), []string{"store"}, time.Hour, join.ErrServerSpec},
		{"s1", nil, time.Hour, join.ErrServerSpec},
		{"s1", []string{"mail"}, time.Hour, join.ErrServerSpec},
		{"s1", []string{""}, time.Hour, join.ErrServerSpec},
		{"s1", []string{"store", "store"}, time.Hour, join.ErrServerSpec},
		{"s1", []string{"store"}, 4*time.Minute + 59*time.Second, join.ErrTTL},
		{"s1", []string{"store"}, 24*time.Hour + time.Second, join.ErrTTL},
	} {
		if _, err := join.AddServer(ctx, e.st, e.service(), c.name, c.roles, c.ttl, now); !errors.Is(err, c.want) {
			t.Errorf("%q %v %s: %v, want %v", c.name, c.roles, c.ttl, err, c.want)
		}
	}
	if n := e.scalar(t, "SELECT count(*) FROM servers"); n != 0 {
		t.Fatalf("%d servers written by refused adds", n)
	}
	for i, ttl := range []time.Duration{5 * time.Minute, 24 * time.Hour} {
		if _, err := join.AddServer(ctx, e.st, e.service(), "s"+strconv.Itoa(i), []string{"store", "edge"}, ttl, now); err != nil {
			t.Errorf("ttl %s: %v", ttl, err)
		}
	}
	if _, err := join.AddServer(ctx, e.st, e.service(), "s0", []string{"edge"}, time.Hour, now); !errors.Is(err, store.ErrExists) {
		t.Errorf("duplicate name: %v", err)
	}
	if n := e.scalar(t, "SELECT count(*) FROM join_tokens WHERE expires_at - created_at = interval '5 minutes'"); n != 1 {
		t.Errorf("%d tokens of 5 minutes", n)
	}
}

// J2, J3: a redeem returns an agent certificate for the server's id, the
// service anchor and its list, and sets joined_at; the token is then
// refused.
func TestRedeem(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tok := e.add(t, "s1", "store")
	csr, key := pkitest.CSR(t)
	resp, err := join.Redeem(ctx, e.st, e.keys, tok, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(resp.AgentCert)
	if err != nil {
		t.Fatal(err)
	}
	id := e.scalar(t, "SELECT id FROM servers WHERE name = 's1'")
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "keepia:agent:"+strconv.FormatInt(id, 10) || !key.PublicKey.Equal(cert.PublicKey) {
		t.Errorf("agent certificate URI %v", cert.URIs)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool(e.keys.Anchor(pki.AnchorAgent).Cert), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Errorf("agent certificate does not chain to the agent anchor: %v", err)
	}
	if string(resp.ServiceAnchor) != string(e.service().Raw) {
		t.Error("the response's service anchor")
	}
	if _, err := pki.VerifyCRL(resp.ServiceCRL, e.service(), nil, now); err != nil {
		t.Errorf("the response's service list: %v", err)
	}
	if n := e.scalar(t, "SELECT count(*) FROM servers WHERE name = 's1' AND joined_at IS NOT NULL"); n != 1 {
		t.Error("joined_at not set")
	}
	_, err = e.redeem(ctx, t, tok, now)
	refusedFor(t, "reuse", err, join.ErrTokenUsed)
	if n := e.scalar(t, "SELECT count(*) FROM certificates WHERE purpose = 'agent'"); n != 1 {
		t.Errorf("%d agent certificates", n)
	}
}

func pool(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

// J5, J6, J7, J8: expiry, a wrong secret that does not burn the token, a
// removed server, and a newer token that invalidates the older one.
func TestRedeemRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	tok := e.add(t, "s1", "store")
	_, err := e.redeem(ctx, t, tok, now.Add(join.DefaultTTL))
	refusedFor(t, "expired", err, join.ErrTokenExpired)

	wrong := tok
	wrong.Secret[0] ^= 1
	_, err = e.redeem(ctx, t, wrong, now)
	refusedFor(t, "wrong secret", err, join.ErrUnknownToken)
	unknown := tok
	unknown.ID[0] ^= 1
	_, err = e.redeem(ctx, t, unknown, now)
	refusedFor(t, "unknown id", err, join.ErrUnknownToken)
	if _, err := e.redeem(ctx, t, tok, now); err != nil {
		t.Errorf("the right secret after a wrong one: %v", err)
	}

	tok2 := e.add(t, "s2", "store")
	if _, err := pki.RevokeServer(ctx, e.st, e.keys, "s2", now); err != nil {
		t.Fatal(err)
	}
	_, err = e.redeem(ctx, t, tok2, now)
	if !errors.Is(err, join.ErrRefused) {
		t.Errorf("removed server: %v", err)
	}
	if _, err := join.NewToken(ctx, e.st, e.service(), "s2", time.Hour, now); !errors.Is(err, join.ErrRemoved) {
		t.Errorf("token for a removed server: %v", err)
	}

	old := e.add(t, "s3", "edge")
	fresh, err := join.NewToken(ctx, e.st, e.service(), "s3", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.redeem(ctx, t, old, now)
	refusedFor(t, "older token", err, join.ErrTokenInvalidated)
	if _, err := e.redeem(ctx, t, fresh, now); err != nil {
		t.Errorf("newer token: %v", err)
	}
	if _, err := join.NewToken(ctx, e.st, e.service(), "s3", time.Hour, now); !errors.Is(err, join.ErrAlreadyJoined) {
		t.Errorf("token for a joined server: %v", err)
	}
	if _, err := join.NewToken(ctx, e.st, e.service(), "nope", time.Hour, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("token for an unknown server: %v", err)
	}
	if _, err := join.Redeem(ctx, e.st, e.keys, fresh, []byte("not a CSR"), now); !errors.Is(err, join.ErrRefused) {
		t.Errorf("bad CSR: %v", err)
	}
}

// heldAt runs f in a goroutine whose hook signals reached and then waits
// for release.
type gate struct {
	reached chan struct{}
	release chan struct{}
}

func newGate(n int) *gate {
	return &gate{reached: make(chan struct{}, n), release: make(chan struct{})}
}

func (g *gate) hook() { g.reached <- struct{}{}; <-g.release }

func (g *gate) wait(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(testwait.Limit(t)):
		t.Fatalf("%s did not reach its hook", what)
	}
}

// J4: of two concurrent redeems of one token, exactly one succeeds. The
// second waits for the first's row lock (pg_stat_activity).
func TestConcurrentRedeems(t *testing.T) {
	e := newEnv(t)
	tok := e.add(t, "s1", "store")
	g := newGate(2)
	ctx := join.WithHooks(context.Background(), join.Hooks{AfterLock: g.hook})
	done := make(chan error, 2)
	for range 2 {
		go func() { _, err := e.redeem(ctx, t, tok, now); done <- err }()
	}
	g.wait(t, "a redeem")
	second := make(chan error, 1)
	go func() {
		select {
		case <-g.reached:
			second <- errors.New("the second redeem got past the locks")
		case <-g.release:
		}
	}()
	storetest.WaitFor(t, e.obs, second, "the second redeem", storetest.LockWaitQuery)
	close(g.release)
	var ok, refused int
	for range 2 {
		if err := <-done; err == nil {
			ok++
		} else if errors.Is(err, join.ErrRefused) {
			refused++
		} else {
			t.Errorf("redeem: %v", err)
		}
	}
	if ok != 1 || refused != 1 {
		t.Errorf("%d succeeded and %d were refused, want 1 and 1", ok, refused)
	}
	if n := e.scalar(t, "SELECT count(*) FROM certificates WHERE purpose = 'agent'"); n != 1 {
		t.Errorf("%d agent certificates", n)
	}
}

// X1: a redeem and a removal of the same server at once do not deadlock.
// The redeem holds the server row when the removal starts; the removal
// waits, then revokes the certificate the redeem issued.
func TestRedeemAndRemoveDoNotDeadlock(t *testing.T) {
	e := newEnv(t)
	tok := e.add(t, "s1", "store")
	g := newGate(1)
	ctx := join.WithHooks(context.Background(), join.Hooks{AfterServerLock: g.hook})
	redeemDone := make(chan error, 1)
	var serial atomic.Pointer[big.Int]
	go func() {
		resp, err := e.redeem(ctx, t, tok, now)
		if err == nil {
			c, perr := x509.ParseCertificate(resp.AgentCert)
			if perr == nil {
				serial.Store(c.SerialNumber)
			}
		}
		redeemDone <- err
	}()
	g.wait(t, "the redeem")
	removeDone := make(chan error, 1)
	go func() { _, err := pki.RevokeServer(context.Background(), e.st, e.keys, "s1", now); removeDone <- err }()
	storetest.WaitFor(t, e.obs, removeDone, "the removal", storetest.LockWaitQuery)
	close(g.release)
	if err := <-redeemDone; err != nil {
		t.Errorf("redeem: %v", err)
	}
	if err := <-removeDone; err != nil {
		t.Errorf("remove: %v", err)
	}
	rows, err := e.st.ListCRLs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Anchor != string(pki.AnchorAgent) {
			continue
		}
		c, err := pki.VerifyCRL(r.DER, e.keys.Anchor(pki.AnchorAgent).Cert, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if s := serial.Load(); s == nil || !c.IsRevoked(s) {
			t.Error("the agent certificate of the redeem is not revoked by the removal")
		}
	}
}

// fakeConn is the join listener as the agent sees it, backed by Redeem.
// It records whether a token ever arrived.
type fakeConn struct {
	e         *env
	peer      []*x509.Certificate
	lists     []byte
	tokenSeen bool
}

func (c *fakeConn) PeerCertificates() []*x509.Certificate { return c.peer }

func (c *fakeConn) FetchLists(context.Context) ([]byte, error) { return c.lists, nil }

func (c *fakeConn) Redeem(ctx context.Context, token string, csr []byte) (*join.Response, error) {
	c.tokenSeen = true
	t, err := join.ParseToken(token)
	if err != nil {
		return nil, err
	}
	return join.Redeem(ctx, c.e.st, c.e.keys, t, csr, now)
}

// listsBody is the lists response: every stored list as PEM, with other
// content around it that the agent must ignore.
func listsBody(t *testing.T, e *env, extra ...[]byte) []byte {
	t.Helper()
	rows, err := e.st.ListCRLs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("not a list\n")
	body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.service().Raw})...)
	for _, r := range rows {
		if r.Anchor == string(pki.AnchorService) {
			body = append(body, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: r.DER})...)
		}
	}
	for _, x := range extra {
		body = append(body, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: x})...)
	}
	return body
}

// J10, C5: the agent checks the pin and the name, then the fetched list,
// and sends the token only when all of them clear the listener.
func TestJoinAgentSide(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	leaf, _, err := pki.IssueControlGate(ctx, e.st, e.keys, now)
	if err != nil {
		t.Fatal(err)
	}
	service := e.service()

	tok := e.add(t, "s1", "store")
	csr, key := pkitest.CSR(t)
	ok := &fakeConn{e: e, peer: []*x509.Certificate{leaf, service}, lists: listsBody(t, e)}
	j, err := join.Join(ctx, ok, tok, csr, &key.PublicKey, now)
	if err != nil {
		t.Fatalf("right pin and name: %v", err)
	}
	if j.AgentCert.URIs[0].Opaque[:len("agent:")] != "agent:" || !j.ServiceAnchor.Equal(service) {
		t.Errorf("joined: %v", j.AgentCert.URIs)
	}

	other := pkitest.NewKeys(t, now)
	wrongPin := tok
	wrongPin.Pin = join.Pin(other.Anchor(pki.AnchorService).Cert)
	c := &fakeConn{e: e, peer: []*x509.Certificate{leaf, service}, lists: listsBody(t, e)}
	if _, err := join.Join(ctx, c, wrongPin, csr, &key.PublicKey, now); !errors.Is(err, join.ErrServer) || c.tokenSeen {
		t.Errorf("wrong pin: %v, token sent %v", err, c.tokenSeen)
	}

	gateLeaf, err := pki.GateLeaf(pki.RoleStore, "s9", 9)
	if err != nil {
		t.Fatal(err)
	}
	storeGate, err := pki.Issue(e.keys.Anchor(pki.AnchorService), gateLeaf, key.Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	tok2 := e.add(t, "s2", "store")
	c = &fakeConn{e: e, peer: []*x509.Certificate{storeGate, service}, lists: listsBody(t, e)}
	if _, err := join.Join(ctx, c, tok2, csr, &key.PublicKey, now); !errors.Is(err, join.ErrServer) || c.tokenSeen {
		t.Errorf("another gate's certificate: %v, token sent %v", err, c.tokenSeen)
	}

	// The control gate's leaf revoked in the fetched list: no token.
	rows, err := e.st.ListCRLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var number int64
	for _, r := range rows {
		if r.Anchor == string(pki.AnchorService) {
			number = r.Number
		}
	}
	revoked, err := pki.CreateCRL(e.keys.Anchor(pki.AnchorService), number+1,
		[]pki.Revoked{{Serial: leaf.SerialNumber, RevokedAt: now, Reason: pki.ReasonKeyCompromise, NotAfter: leaf.NotAfter}}, now)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: revoked})
	c = &fakeConn{e: e, peer: []*x509.Certificate{leaf, service}, lists: body}
	if _, err := join.Join(ctx, c, tok2, csr, &key.PublicKey, now); !errors.Is(err, pki.ErrRevoked) || c.tokenSeen {
		t.Errorf("revoked listener: %v, token sent %v", err, c.tokenSeen)
	}
	if n := e.scalar(t, "SELECT count(*) FROM servers WHERE name = 's2' AND joined_at IS NULL"); n != 1 {
		t.Error("s2 joined through a refused listener")
	}
}

// J11: fetched lists authenticate themselves: a list of an anchor the
// agent does not hold, a stale one and a lower-numbered one are refused,
// and content other than lists is ignored.
func TestVerifyFetchedLists(t *testing.T) {
	keys := pkitest.NewKeys(t, now.Add(-30*24*time.Hour))
	other := pkitest.NewKeys(t, now)
	service := keys.Anchor(pki.AnchorService)
	held := map[pki.AnchorName]*x509.Certificate{pki.AnchorService: service.Cert}
	mk := func(a *pki.Anchor, n int64, at time.Time) []byte {
		der, err := pki.CreateCRL(a, n, nil, at)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	current := mk(service, 5, now)
	got, err := join.VerifyFetchedLists(join.ParseLists(append([]byte("junk\n"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: current})...)), held, nil, now)
	if err != nil || len(got) != 1 || got[pki.AnchorService].Number.Int64() != 5 {
		t.Fatalf("current list: %v, %v", got, err)
	}
	heldList := got
	body := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Anchor(pki.AnchorService).Cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})...)
	if lists := join.ParseLists(body); len(lists) != 0 {
		t.Errorf("non-list content became %d lists", len(lists))
	}
	for name, c := range map[string]struct {
		lists [][]byte
		want  error
	}{
		"unknown anchor": {[][]byte{mk(other.Anchor(pki.AnchorService), 9, now)}, join.ErrLists},
		"agent anchor":   {[][]byte{mk(keys.Anchor(pki.AnchorAgent), 9, now)}, join.ErrLists},
		"stale":          {[][]byte{mk(service, 9, now.Add(-7*24*time.Hour))}, pki.ErrCRLExpired},
		"lower number":   {[][]byte{mk(service, 4, now)}, pki.ErrCRLRollback},
		"two lists":      {[][]byte{mk(service, 6, now), mk(service, 7, now)}, join.ErrLists},
		"garbage":        {[][]byte{{0x30, 0x01}}, join.ErrLists},
	} {
		if _, err := join.VerifyFetchedLists(c.lists, held, heldList, now); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if _, err := join.VerifyFetchedLists([][]byte{current}, held, heldList, now); err != nil {
		t.Errorf("the held list again: %v", err)
	}
	if err := join.CheckLeaf(service.Cert, nil); err == nil {
		t.Error("CheckLeaf without a list")
	}
}
