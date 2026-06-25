package analyze

import (
	"os"
	"path/filepath"
)

// errString is a minimal error for constructing ImageScan.Err in tests.
type errString string

func (e errString) Error() string { return string(e) }

// readSample loads the scanner package's handcrafted fixture so analyze can be
// exercised against the same realistic shape the scanner validates.
func readSample() ([]byte, error) {
	return os.ReadFile(filepath.Join("..", "scanner", "testdata", "sample.json"))
}
