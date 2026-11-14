package bench

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CommittedFile checks that path is tracked by Git and byte-identical to its
// version at HEAD, and returns the HEAD commit. A protocol that is not
// committed, or that was edited after its commit, is not a frozen protocol.
func CommittedFile(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err == nil {
		abs, err = filepath.EvalSymlinks(abs)
	}
	if err != nil {
		return "", err
	}
	output, err := gitOutput(filepath.Dir(abs), "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("%s is not inside a Git checkout", path)
	}
	top, err := filepath.EvalSymlinks(strings.TrimSpace(string(output)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(top, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%s is outside its Git checkout", path)
	}
	committed, err := gitOutput(top, "cat-file", "blob", "HEAD:"+filepath.ToSlash(rel))
	if err != nil {
		return "", fmt.Errorf("%s is not committed at HEAD", path)
	}
	current, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(current, committed) {
		return "", fmt.Errorf("%s differs from its committed version", path)
	}
	commit, err := gitOutput(top, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(commit)), nil
}

func gitOutput(dir string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	return command.Output()
}
