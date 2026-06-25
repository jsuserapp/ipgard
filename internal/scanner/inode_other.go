//go:build !linux

package scanner

import "os"

func fileInode(info os.FileInfo) uint64 {
	return 0
}
