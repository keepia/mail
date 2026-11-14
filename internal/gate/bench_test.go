//go:build linux

package gate

import (
	"bufio"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/testwait"
)

// B1: one full mTLS handshake at the store's IMAP listener, both sides in
// this process over net.Pipe: the gate's GetConfigForClient snapshot and
// VerifyClient, and the client's own work. The server's share is below
// this figure; BenchmarkVerifyClient is the gate's check alone.
func BenchmarkIngressHandshake(b *testing.B) {
	now := time.Now()
	f := newFixture(b, RoleStore, now)
	m, err := buildTLS(RoleStore, f.bundle(RoleStore, f.lists(RoleStore, 1, now)), nil, now)
	if err != nil {
		b.Fatal(err)
	}
	g := &Gate{clock: SystemClock{}}
	g.mat.Store(m)
	client := f.edgeDovecot(7, now)
	roots := x509.NewCertPool()
	roots.AddCert(f.service.Cert)
	ccfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: f.gateName,
		Certificates: []tls.Certificate{*client.tlsCert()}}
	spec := specs[RoleStore][0]
	errc := make(chan error, 1)
	for b.Loop() {
		c1, c2 := net.Pipe()
		h := &handshake{g: g, spec: spec}
		srv := tls.Server(c1, h.config())
		cli := tls.Client(c2, ccfg)
		go func() { errc <- cli.Handshake() }()
		if err := srv.Handshake(); err != nil {
			b.Fatal(err)
		}
		if err := <-errc; err != nil {
			b.Fatal(err)
		}
		if h.chain == nil {
			b.Fatal("the client was not verified")
		}
		_ = c1.Close()
		_ = c2.Close()
	}
}

// B1: the gate's certificate check per handshake.
func BenchmarkVerifyClient(b *testing.B) {
	now := time.Now()
	f := newFixture(b, RoleStore, now)
	m, err := buildTLS(RoleStore, f.bundle(RoleStore, f.lists(RoleStore, 1, now)), nil, now)
	if err != nil {
		b.Fatal(err)
	}
	chain := []*x509.Certificate{f.edgeDovecot(7, now).cert}
	for b.Loop() {
		if _, err := pki.VerifyClient(chain, m.anchors[pki.AnchorStoreClient], []pki.Purpose{pki.PurposeEdgeDovecot}, m.lists[pki.AnchorStoreClient], now); err != nil {
			b.Fatal(err)
		}
	}
}

// ---- V1: memory per session, measured on a gate in its own process ----

const childEnv = "KEEPIA_GATE_CHILD"

// TestGateProcess is the gate of BenchmarkSessionMemory, in a child
// process; it does nothing in a normal test run.
func TestGateProcess(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		t.Skip("only as BenchmarkSessionMemory's child")
	}
	dir := os.Getenv("KEEPIA_GATE_DIR")
	ip := func(name string) netip.Addr { return netip.MustParseAddr(os.Getenv(name)) }
	role := Role(os.Getenv("KEEPIA_GATE_ROLE"))
	cfg := Config{Role: role, Private: []netip.Addr{ip("KEEPIA_GATE_PRIVATE")}, Dir: dir, MaxConns: DefaultMaxConns[role],
		MeshNet: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Control: ip("KEEPIA_GATE_PRIVATE")}
	target := os.Getenv("KEEPIA_GATE_TARGET")
	if role == RoleStore {
		cfg.Mesh, cfg.Target = []netip.Addr{ip("KEEPIA_GATE_MESH")}, ip("KEEPIA_GATE_MESH")
	}
	var d net.Dialer
	g, err := New(cfg, Options{
		Log:            slog.New(slog.NewTextHandler(os.Stdout, nil)),
		ReadGeneration: readGeneration,
		LoadBundle:     loadDERFiles,
		HealthAddr:     netip.AddrPortFrom(ip("KEEPIA_GATE_PRIVATE"), 0).String(),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if role == RoleStore {
				addr = target
			}
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// "stats" prints the runtime's memory figures; the parent closes
		// stdin to stop the gate.
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			runtime.GC()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if hp := os.Getenv("KEEPIA_GATE_HEAPPROFILE"); hp != "" {
				if f, err := os.Create(hp); err == nil {
					_ = pprof.WriteHeapProfile(f)
					_ = f.Close()
				}
			}
			fmt.Printf("memstats heap=%d stack=%d goroutines=%d\n", ms.HeapInuse, ms.StackInuse, runtime.NumGoroutine())
		}
		cancel()
	}()
	if err := g.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

// loadDERFiles is the child's bundle loader: DER files the benchmark
// wrote (part 2 reads gatebundle's format instead).
func loadDERFiles(dir string) (*Bundle, error) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			panic(err)
		}
		return b
	}
	parse := func(name string) *x509.Certificate {
		c, err := x509.ParseCertificate(read(name))
		if err != nil {
			panic(err)
		}
		return c
	}
	k, err := x509.ParsePKCS8PrivateKey(read("key.der"))
	if err != nil {
		return nil, errors.New("key.der does not parse")
	}
	service := parse("service.der")
	return &Bundle{
		Chain: []*x509.Certificate{parse("leaf.der"), service},
		Key:   k.(crypto.Signer),
		Anchors: map[pki.AnchorName]*x509.Certificate{
			pki.AnchorService: service, pki.AnchorStoreClient: parse("store-client.der"),
		},
		Lists: map[pki.AnchorName][]byte{
			pki.AnchorService: read("list-service.der"), pki.AnchorStoreClient: read("list-store-client.der"),
		},
	}, nil
}

// echoServer echoes every connection without keeping its bytes.
func echoServer(b *testing.B, addr string) net.Listener {
	b.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln
}

// procStatus reads the child's VmRSS, VmHWM (KiB) and thread count.
func procStatus(b *testing.B, pid int) (rss, hwm, threads int) {
	b.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		b.Fatal(err)
	}
	for _, l := range strings.Split(string(raw), "\n") {
		k, v, _ := strings.Cut(l, ":")
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(v), " kB"))
		switch k {
		case "VmRSS":
			rss = n
		case "VmHWM":
			hwm = n
		case "Threads":
			threads = n
		}
	}
	return rss, hwm, threads
}

func fdCount(b *testing.B, pid int) int {
	b.Helper()
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		b.Fatal(err)
	}
	return len(ents)
}

// BenchmarkSessionMemory (V1, V2) runs a store gate and an edge gate in
// child processes with GOMAXPROCS=2 and GOMEMLIMIT=24MiB, as part 2's
// Compose sets them, fills each to its connection cap with sessions that
// each moved 80 KiB both ways, then runs 4 concurrent 1 MiB transfers,
// and reports the child's RSS per session, its peak, its threads and file
// descriptors, and the runtime's heap and stack per session after a GC.
// Kernel socket and pipe buffers are not in RSS; part 2's test 18 reads
// the cgroup's memory.peak. Run it with -benchtime=1x; with
// KEEPIA_GATE_HEAPPROFILE=<file> the child also writes a heap profile.
func BenchmarkSessionMemory(b *testing.B) {
	for _, role := range []Role{RoleStore, RoleEdge} {
		b.Run(string(role), func(b *testing.B) {
			for b.Loop() {
				measureSessions(b, role)
			}
		})
	}
}

func measureSessions(b *testing.B, role Role) {
	now := time.Now()
	f := newFixture(b, RoleStore, now)
	dir := b.TempDir()
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	mesh, priv, remote := testIP(b), testIP(b), testIP(b)
	var target net.Listener
	if role == RoleStore {
		key, err := x509.MarshalPKCS8PrivateKey(f.gate.key)
		if err != nil {
			b.Fatal(err)
		}
		lists := f.lists(RoleStore, 1, now)
		write("leaf.der", f.gate.cert.Raw)
		write("key.der", key)
		write("service.der", f.service.Cert.Raw)
		write("store-client.der", f.storeClient.Cert.Raw)
		write("list-service.der", lists[pki.AnchorService])
		write("list-store-client.der", lists[pki.AnchorStoreClient])
		target = echoServer(b, netip.AddrPortFrom(remote, 0).String())
	} else {
		target = echoServer(b, netip.AddrPortFrom(remote, PortIMAP).String())
		write(EgressFileName, []byte(fmt.Sprintf(`{"version":1,"listeners":[{"port":20000,"remote":"%s","store":"s1.store.keepia.internal"}]}`, target.Addr())))
	}
	write(GenerationFileName, []byte("1\n"))

	cmd := exec.Command(os.Args[0], "-test.run=^TestGateProcess$")
	cmd.Env = append(os.Environ(), childEnv+"=1", "GOMAXPROCS=2", "GOMEMLIMIT=24MiB",
		"KEEPIA_GATE_ROLE="+string(role), "KEEPIA_GATE_DIR="+dir, "KEEPIA_GATE_MESH="+mesh.String(),
		"KEEPIA_GATE_PRIVATE="+priv.String(), "KEEPIA_GATE_TARGET="+target.Addr().String())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		b.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		b.Fatal(err)
	}
	applied := make(chan struct{})
	stats := make(chan [3]int, 4)
	go func() {
		sc := bufio.NewScanner(stdout)
		once := sync.Once{}
		for sc.Scan() {
			if strings.Contains(sc.Text(), `msg="applied generation 1"`) {
				once.Do(func() { close(applied) })
			}
			var s [3]int
			if _, err := fmt.Sscanf(sc.Text(), "memstats heap=%d stack=%d goroutines=%d", &s[0], &s[1], &s[2]); err == nil {
				stats <- s
			}
		}
	}()
	memstats := func() [3]int {
		if _, err := io.WriteString(stdin, "stats\n"); err != nil {
			b.Fatal(err)
		}
		select {
		case s := <-stats:
			return s
		case <-time.After(testwait.Limit(b)):
			b.Fatal("no memstats from the child")
			return [3]int{}
		}
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}()
	select {
	case <-applied:
	case <-time.After(testwait.Limit(b)):
		b.Fatal("the child gate did not apply its material")
	}
	pid := cmd.Process.Pid
	ms0 := memstats()
	rss0, _, threads0 := procStatus(b, pid)

	roots := x509.NewCertPool()
	roots.AddCert(f.service.Cert)
	client := f.edgeDovecot(7, now)
	ccfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: f.gateName,
		Certificates: []tls.Certificate{*client.tlsCert()}}
	n := DefaultMaxConns[role]
	payload := make([]byte, 80<<10)
	conns := make([]net.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	roundTrip := func(c net.Conn, p []byte) {
		errc := make(chan error, 1)
		go func() { _, err := c.Write(p); errc <- err }()
		if _, err := io.ReadFull(c, make([]byte, len(p))); err != nil {
			b.Fatal(err)
		}
		if err := <-errc; err != nil {
			b.Fatal(err)
		}
	}
	for range n {
		var c net.Conn
		var err error
		if role == RoleStore {
			c, err = tls.Dial("tcp", netip.AddrPortFrom(mesh, PortIMAP).String(), ccfg)
		} else {
			c, err = net.Dial("tcp", netip.AddrPortFrom(priv, 20000).String())
		}
		if err != nil {
			b.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(testwait.Limit(b)))
		roundTrip(c, payload)
		conns = append(conns, c)
	}
	rss1, _, threads1 := procStatus(b, pid)
	ms1 := memstats()
	b.ReportMetric(float64(ms1[0]-ms0[0])/1024/float64(n), "heap-KiB/session")
	b.ReportMetric(float64(ms1[1]-ms0[1])/1024/float64(n), "stack-KiB/session")
	b.ReportMetric(float64(ms1[2]-ms0[2])/float64(n), "goroutines/session")
	big := make([]byte, 1<<20)
	var wg sync.WaitGroup
	for _, c := range conns[:4] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			roundTrip(c, big)
		}()
	}
	wg.Wait()
	rss2, hwm, threads2 := procStatus(b, pid)
	fds := fdCount(b, pid)
	perSession := float64(rss1-rss0) / float64(n)
	b.ReportMetric(float64(rss0)/1024, "MiB-idle")
	b.ReportMetric(float64(rss1)/1024, "MiB-full")
	b.ReportMetric(float64(rss2)/1024, "MiB-after-1MiB")
	b.ReportMetric(float64(hwm)/1024, "MiB-peak")
	b.ReportMetric(perSession, "KiB/session")
	b.ReportMetric(float64(max(threads0, threads1, threads2)), "threads")
	b.ReportMetric(float64(fds), "fds")
	b.ReportMetric(float64(n), "sessions")
}
