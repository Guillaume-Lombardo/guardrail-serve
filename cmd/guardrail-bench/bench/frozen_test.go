package bench

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCommittedFileRefusesUncommittedOrEditedProtocols(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=bench", "-c", "user.email=bench@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	path := filepath.Join(dir, "protocol.json")
	if err := os.WriteFile(path, []byte(`{"threshold":0.99}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CommittedFile(path); err == nil {
		t.Fatal("an uncommitted protocol was accepted")
	}
	git("add", "protocol.json")
	git("commit", "-q", "-m", "freeze")
	commit, err := CommittedFile(path)
	if err != nil || len(commit) != 40 {
		t.Fatalf("committed protocol: %q %v", commit, err)
	}
	if err := os.WriteFile(path, []byte(`{"threshold":0.5}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CommittedFile(path); err == nil {
		t.Fatal("a protocol edited after its commit was accepted")
	}
}
