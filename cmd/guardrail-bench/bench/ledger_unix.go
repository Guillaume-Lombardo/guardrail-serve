//go:build unix

package bench

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive, non-blocking lock released when the file closes.
func lockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
