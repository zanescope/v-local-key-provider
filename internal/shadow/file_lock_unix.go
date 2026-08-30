//go:build darwin

package shadow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const attemptLockLeaf = "attempt.lock"

type FileLocker struct {
	root   string
	uid    uint32
	device uint64
	inode  uint64
}

func NewFileLocker(root string) (*FileLocker, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("shadow lock root must be absolute")
	}
	root = filepath.Clean(root)
	if err := ensurePrivateRoot(root); err != nil {
		return nil, err
	}
	uid := uint32(os.Geteuid())
	fd, stat, err := openRecoveryRoot(root, uid, 0, 0, false)
	if err != nil {
		return nil, err
	}
	_ = unix.Close(fd)
	return &FileLocker{root: root, uid: uid, device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func validateLockFD(fd int, uid uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Uid != uid || stat.Nlink != 1 || stat.Size != 0 {
		return errors.New("shadow attempt lock identity is unsafe")
	}
	return nil
}

func (value *FileLocker) Acquire(ctx context.Context) (func() error, error) {
	if value == nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("shadow attempt lock request is invalid")
	}
	rootFD, _, err := openRecoveryRoot(value.root, value.uid, value.device, value.inode, true)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(rootFD, attemptLockLeaf,
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	_ = unix.Close(rootFD)
	if err != nil {
		return nil, err
	}
	if err := validateLockFD(fd, value.uid); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = unix.Close(fd)
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = unix.Close(fd)
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			releaseErr = errors.Join(unix.Flock(fd, unix.LOCK_UN), unix.Close(fd))
		})
		return releaseErr
	}, nil
}
