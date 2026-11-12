package server

import "os"

// CIProof is the CI proof (plan test 10) for the lint job: its error is
// deliberately not checked. Reverted next.
func CIProof() {
	os.Remove("ci-proof-does-not-exist")
}
