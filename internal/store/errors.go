package store

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// The kinds of a refused write. Errors of the data model's API wrap one
// of them, or ErrLockTimeout (locks.go) for a lock not granted within the
// lock timeout (55P03, WithLockTimeout); test with errors.Is.
var (
	// ErrNotFound: a named row does not exist (also a foreign key, 23503).
	ErrNotFound = errors.New("not found")
	// ErrExists: a unique constraint, domain_name_taken or address_taken
	// (23505).
	ErrExists = errors.New("already exists")
	// ErrRefused: a CHECK or a rule of a trigger (23514), a delete of a
	// row that others reference (RESTRICT, 23001), or
	// read_committed_required (25001).
	ErrRefused = errors.New("refused")
)

// RuleError is a write refused by a constraint or trigger of the schema.
// Its text is the database's fixed message and the rule's name, never a
// value of the row: PostgreSQL's DETAIL, which quotes the row, is dropped.
type RuleError struct {
	// Kind is ErrExists, ErrRefused or ErrNotFound.
	Kind error
	// Rule is the constraint or trigger name, such as address_taken or
	// mailboxes_password_hash_format.
	Rule    string
	message string
}

func (e *RuleError) Error() string { return e.message + " (rule " + e.Rule + ")" }

// Unwrap returns Kind.
func (e *RuleError) Unwrap() error { return e.Kind }

// Rule returns the rule name of the RuleError that err wraps, or "".
func Rule(err error) string {
	var re *RuleError
	if errors.As(err, &re) {
		return re.Rule
	}
	return ""
}

// mapError maps a PostgreSQL error to the API's kinds by SQLSTATE and
// constraint name. Other errors, and nil, are returned as they are.
func mapError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	var kind error
	switch pgErr.Code {
	case "23505":
		kind = ErrExists
	case "23514", "23001", "25001":
		kind = ErrRefused
	case "23503":
		kind = ErrNotFound
	case "55P03":
		return fmt.Errorf("%w: %s", ErrLockTimeout, pgErr.Message)
	default:
		return err
	}
	return &RuleError{Kind: kind, Rule: pgErr.ConstraintName, message: pgErr.Message}
}

// notFound is ErrNotFound for the row named by what and name.
func notFound(what, name string) error {
	return fmt.Errorf("%s %s: %w", what, name, ErrNotFound)
}
