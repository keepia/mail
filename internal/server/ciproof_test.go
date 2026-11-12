package server

import "testing"

// CI proof (plan test 10): the test job must go red. Reverted next.
func TestCIProofRed(t *testing.T) {
	t.Fatal("CI proof: test job must go red")
}
