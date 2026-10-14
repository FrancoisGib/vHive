// MIT License
//
// Copyright (c) 2026 vHive team
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package podcgroup puts the processes of a sandbox in a cgroup of their own in the cgroup of their pod,
// <pod cgroup>/<name>, so that the pod accounts for the sandbox (CPU, memory) as for a container: for the VMs, whose
// processes are not started by the container runtime of Kubernetes. Before the pod is deleted, the processes go back
// to their cgroup and the cgroup is deleted. Only with cgroup v2.
package podcgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	// Root is the mount point of cgroup v2, and Proc that of procfs (both changed by tests).
	Root = "/sys/fs/cgroup"
	Proc = "/proc"
	// RemoveDir deletes the directory of a cgroup (rmdir: a cgroup directory is deleted with its files).
	RemoveDir = os.Remove
)

// Cgroup is the cgroup of a sandbox in the cgroup of its pod.
type Cgroup struct {
	// Path is the directory of the cgroup.
	Path string
	// the cgroup of each process before it was moved
	origins map[int]string
	// the cgroup of the first process moved: that of the processes born in this cgroup
	home string
}

// Available tells whether cgroup v2 is mounted.
func Available() error {
	if _, err := os.Stat(filepath.Join(Root, "cgroup.controllers")); err != nil {
		return errors.New("cgroup v2 is not mounted")
	}
	return nil
}

// PodPath returns the directory of the cgroup of a pod, from its CgroupParent: a systemd slice
// (kubepods-besteffort-pod<uid>.slice, in kubepods.slice/kubepods-besteffort.slice) or a cgroupfs path.
func PodPath(parent string) string {
	if !strings.HasSuffix(parent, ".slice") || strings.Contains(parent, "/") {
		return filepath.Join(Root, parent)
	}
	parts := strings.Split(strings.TrimSuffix(parent, ".slice"), "-")
	dirs := []string{Root}
	for i := range parts {
		dirs = append(dirs, strings.Join(parts[:i+1], "-")+".slice")
	}
	return filepath.Join(dirs...)
}

// New creates the cgroup <cgroup of the pod>/<name>, empty.
func New(name, cgroupParent string) (*Cgroup, error) {
	if err := Available(); err != nil {
		return nil, err
	}
	if cgroupParent == "" {
		return nil, errors.New("the pod has no cgroup parent")
	}
	pod := PodPath(cgroupParent)
	if _, err := os.Stat(pod); err != nil {
		return nil, fmt.Errorf("no cgroup for the pod: %w", err)
	}
	c := &Cgroup{Path: filepath.Join(pod, name), origins: make(map[int]string)}
	if err := os.Mkdir(c.Path, 0o755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	return c, nil
}

// ProcessCgroup returns the cgroup v2 directory of a process.
func ProcessCgroup(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join(Proc, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(Root, rel), nil
		}
	}
	return "", fmt.Errorf("process %d has no cgroup v2", pid)
}

// AllPIDs returns every process of /proc.
func AllPIDs() ([]int, error) {
	entries, err := os.ReadDir(Proc)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// PIDs returns the processes of a cgroup.
func PIDs(cgroup string) ([]int, error) {
	data, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, field := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(field); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func writePID(cgroup string, pid int) error {
	return os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
}

// Adopt moves a process to the cgroup.
func (c *Cgroup) Adopt(pid int) error {
	origin, err := ProcessCgroup(pid)
	if err != nil || origin == c.Path {
		return nil // gone, or already there
	}
	if err := writePID(c.Path, pid); err != nil {
		return fmt.Errorf("failed to move process %d to %s: %w", pid, c.Path, err)
	}
	c.origins[pid] = origin
	if c.home == "" {
		c.home = origin
	}
	return nil
}

// Adopted returns the number of processes moved to the cgroup.
func (c *Cgroup) Adopted() int {
	return len(c.origins)
}

// Release moves the processes of the cgroup back to their cgroups (those born in this cgroup to the one of the first
// process moved, and to the root cgroup when theirs is gone) and deletes the cgroup, so that the cgroup of its pod
// can be deleted.
func (c *Cgroup) Release() error {
	if pids, err := PIDs(c.Path); err == nil {
		for _, pid := range pids {
			origin, ok := c.origins[pid]
			if !ok {
				origin = c.home
			}
			if origin == "" || writePID(origin, pid) != nil {
				_ = writePID(Root, pid)
			}
		}
	}
	if err := RemoveDir(c.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
