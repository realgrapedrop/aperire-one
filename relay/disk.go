package main

import "syscall"

// readStatfs returns (usedBytes, totalBytes) for a filesystem path. Uses
// the same inputs the dashboard's prototype bridge does (fs.statfs in Node),
// yielding identical numbers for the Disk row.
func readStatfs(path string) (used, total uint64, err error) {
	var s syscall.Statfs_t
	if err = syscall.Statfs(path, &s); err != nil {
		return 0, 0, err
	}
	total = s.Blocks * uint64(s.Bsize)
	free := s.Bfree * uint64(s.Bsize)
	if free > total {
		// Defensive — shouldn't happen, but truncate rather than report
		// a negative delta if the kernel ever returns weird values.
		free = total
	}
	used = total - free
	return used, total, nil
}
