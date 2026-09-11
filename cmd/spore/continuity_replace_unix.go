//go:build !windows

package main

import "os"

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}
