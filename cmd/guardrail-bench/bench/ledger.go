package bench

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// LedgerTotals is what earlier attempts recorded in a ledger already cost.
type LedgerTotals struct {
	Calls    int     `json:"calls"`
	SpentUSD float64 `json:"spent_usd"`
}

// Ledger is the durable record of every paid attempt. The judge budget is
// cumulative over it: a new run, or a new process, starts from what the ledger
// already holds, so rerunning the bench never resets the caps. A file ledger
// is held under an exclusive lock for its whole life, so two processes can
// never spend against the same caps at the same time.
type Ledger struct {
	w     io.Writer
	file  *os.File
	prior LedgerTotals
}

// OpenLedger locks the private paid-call ledger, reads what it already holds
// and appends to it. A line it cannot read refuses the ledger: an unknown past
// spend must never be counted as zero.
func OpenLedger(path string) (*Ledger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("judge ledger %s is held by another bench process: %w", path, err)
	}
	prior, err := readLedger(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("judge ledger %s: %w", path, err)
	}
	return &Ledger{w: file, file: file, prior: prior}, nil
}

func readLedger(r io.Reader) (LedgerTotals, error) {
	var totals LedgerTotals
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for n := 1; scanner.Scan(); n++ {
		data := bytes.TrimSpace(scanner.Bytes())
		if len(data) == 0 {
			continue
		}
		var line LedgerLine
		if err := json.Unmarshal(data, &line); err != nil || line.CostUSD < 0 {
			return LedgerTotals{}, fmt.Errorf("line %d is not a ledger line", n)
		}
		// An attempt of unknown billing already records the worst case as its cost.
		totals.Calls++
		totals.SpentUSD += line.CostUSD
	}
	if err := scanner.Err(); err != nil {
		return LedgerTotals{}, err
	}
	return totals, nil
}

// Prior is what the ledger held when it was opened.
func (l *Ledger) Prior() LedgerTotals { return l.prior }

func (l *Ledger) Write(p []byte) (int, error) { return l.w.Write(p) }

// Close releases the lock.
func (l *Ledger) Close() error {
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

var errLockUnsupported = errors.New("file locking is not supported on this platform")
