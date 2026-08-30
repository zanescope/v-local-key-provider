//go:build !darwin && !windows

package shadow

import "errors"

type FileJournal struct{}

func NewFileJournal(string) (*FileJournal, error) {
	return nil, errors.New("macOS Shadow recovery journal is unavailable")
}
