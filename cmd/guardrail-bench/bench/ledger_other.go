//go:build !unix

package bench

import "os"

// lockFile refuses paid traffic where the ledger cannot be locked.
func lockFile(*os.File) error { return errLockUnsupported }
