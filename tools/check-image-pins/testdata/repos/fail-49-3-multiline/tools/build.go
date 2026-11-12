package main

import (
	"os"
	"os/exec"
)

// A list split over lines, as gofmt writes a long call.
func main() {
	cmd := exec.Command(
		"docker",
		"build",
		".",
	)
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}
