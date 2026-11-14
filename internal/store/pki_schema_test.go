package store_test

import (
	"fmt"
	"testing"
)

// #96 part 2 (00005_pki.sql): every CHECK and foreign key of the
// certificates, anchor_crls and join_tokens tables refuses a bad row and
// accepts a good one next to it.
func TestPKIConstraints(t *testing.T) {
	d := newTestDB(t)
	f := seed(t, d)
	// cert inserts a certificate row; the arguments are SQL literals.
	cert := func(serial, anchor, server, purpose, dns, spki, notAfter, revokedAt, reason string) []string {
		return one(`INSERT INTO certificates (serial, anchor, server_id, purpose, dns_name, spki_sha256, not_before, not_after, der, revoked_at, revocation_reason)
			VALUES (%s, '%s', %s, '%s', %s, %s, '2026-11-14T12:00:00Z', %s, '\x3000', %s, %s)`,
			serial, anchor, server, purpose, dns, spki, notAfter, revokedAt, reason)
	}
	srv := fmt.Sprint(f.srv1)
	const (
		s1     = `'\x01'`
		spki   = `decode(repeat('ab', 32), 'hex')`
		after  = `'2026-12-14T12:00:00Z'`
		before = `'2026-11-14T11:00:00Z'`
	)
	crl := func(anchor, number, next string) []string {
		return one(`INSERT INTO anchor_crls (anchor, number, this_update, next_update, der) VALUES ('%s', %s, '2026-11-14T12:00:00Z', %s, '\x3000')`,
			anchor, number, next)
	}
	token := func(id, server, secret, expires string) []string {
		return one(`INSERT INTO join_tokens (id, server_id, secret_sha256, created_at, expires_at) VALUES (%s, %s, %s, '2026-11-14T12:00:00Z', %s)`,
			id, server, secret, expires)
	}
	const check, fk = "23514", "23503"
	id16, sha := `decode(repeat('01', 16), 'hex')`, `decode(repeat('02', 32), 'hex')`
	runRuleCases(t, d.conn, []ruleCase{
		{"serial empty", cert(`''`, "agent", srv, "agent", "NULL", spki, after, "NULL", "NULL"), false, check, "certificates_serial_length"},
		{"serial 21 bytes", cert(`decode(repeat('01', 21), 'hex')`, "agent", srv, "agent", "NULL", spki, after, "NULL", "NULL"), false, check, "certificates_serial_length"},
		{"serial 20 bytes", cert(`decode(repeat('01', 20), 'hex')`, "agent", srv, "agent", "NULL", spki, after, "NULL", "NULL"), false, "", ""},
		{"anchor unknown", cert(s1, "root", srv, "agent", "NULL", spki, after, "NULL", "NULL"), false, check, "certificates_anchor_valid"},
		{"purpose unknown", cert(s1, "agent", srv, "mail", "NULL", spki, after, "NULL", "NULL"), false, check, "certificates_purpose_valid"},
		{"spki 31 bytes", cert(s1, "agent", srv, "agent", "NULL", `decode(repeat('ab', 31), 'hex')`, after, "NULL", "NULL"), false, check, "certificates_spki_sha256_length"},
		{"not_after before not_before", cert(s1, "agent", srv, "agent", "NULL", spki, before, "NULL", "NULL"), false, check, "certificates_validity"},
		{"revoked without reason", cert(s1, "agent", srv, "agent", "NULL", spki, after, "now()", "NULL"), false, check, "certificates_revocation"},
		{"reason without revocation", cert(s1, "agent", srv, "agent", "NULL", spki, after, "NULL", "5"), false, check, "certificates_revocation"},
		{"revoked with reason", cert(s1, "agent", srv, "agent", "NULL", spki, after, "now()", "5"), false, "", ""},
		{"no server, not the control gate", cert(s1, "agent", "NULL", "agent", "NULL", spki, after, "NULL", "NULL"), false, check, "certificates_control_gate"},
		{"control gate with a server", cert(s1, "service", srv, "control-gate", "'control.keepia.internal'", spki, after, "NULL", "NULL"), false, check, "certificates_control_gate"},
		{"control gate", cert(s1, "service", "NULL", "control-gate", "'control.keepia.internal'", spki, after, "NULL", "NULL"), false, "", ""},
		{"gate without DNS name", cert(s1, "service", srv, "gate", "NULL", spki, after, "NULL", "NULL"), false, check, "certificates_server_dns_name"},
		{"client with DNS name", cert(s1, "agent", srv, "agent", "'srv1.keepia.internal'", spki, after, "NULL", "NULL"), false, check, "certificates_server_dns_name"},
		{"store gate", cert(s1, "service", srv, "gate", "'srv1.store.keepia.internal'", spki, after, "NULL", "NULL"), false, "", ""},
		{"unknown server", cert(s1, "agent", "999999", "agent", "NULL", spki, after, "NULL", "NULL"), false, fk, "certificates_server_id_fkey"},
		{"list anchor unknown", crl("root", "1", after), false, check, "anchor_crls_anchor_valid"},
		{"list number 0", crl("agent", "0", after), false, check, "anchor_crls_number_positive"},
		{"list next before this", crl("agent", "1", before), false, check, "anchor_crls_validity"},
		{"list", crl("agent", "1", after), false, "", ""},
		{"token id 15 bytes", token(`decode(repeat('01', 15), 'hex')`, srv, sha, after), false, check, "join_tokens_id_length"},
		{"token secret hash 31 bytes", token(id16, srv, `decode(repeat('02', 31), 'hex')`, after), false, check, "join_tokens_secret_sha256_length"},
		{"token expires at creation", token(id16, srv, sha, `'2026-11-14T12:00:00Z'`), false, check, "join_tokens_lifetime"},
		{"token unknown server", token(id16, "999999", sha, after), false, fk, "join_tokens_server_id_fkey"},
		{"token", token(id16, srv, sha, after), false, "", ""},
	})
}
