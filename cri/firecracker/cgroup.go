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

package firecracker

// The processes of a VM, its firecracker-containerd shim and its firecracker VMM, run in the cgroup of
// firecracker-containerd, shared by all the VMs: the pod of a function accounts for its placeholder container only.
// They are moved to a cgroup of their own in the cgroup of the pod, <pod cgroup>/vhive-vm-<vmID>, so that the pod
// accounts for the VM (CPU, memory) as for a container. While the VM is created, they are moved as soon as they
// appear (watchVM): the pod accounts for its boot too. Before the pod is deleted, they go back to their cgroup and the
// cgroup of the VM is deleted. Only with cgroup v2.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	vmCgroupPrefix = "vhive-vm-"
	// set by firecracker-containerd in the environment of the shim of a VM, inherited by its VMM
	vmIDEnv = "FIRECRACKER_VM_ID"
	// the processes of firecracker-containerd while a VM is created: a new one is found after this time at most
	watchPeriod = 5 * time.Millisecond
	// a new process is checked during its first checks only: before its exec, it is a copy of its parent
	watchChecks = 10
	// the name of the firecracker-containerd daemon (/proc/<pid>/comm, 15 characters)
	fccdComm = "firecracker-con"
)

var (
	cgroupRoot = "/sys/fs/cgroup"
	procRoot   = "/proc"
	// rmdir: a cgroup directory is deleted with its files
	removeCgroup = os.Remove
)

// vmCgroup is the cgroup of a VM in the cgroup of its pod.
type vmCgroup struct {
	path string
	// the cgroup of each process before it was moved
	origins map[int]string
	// the cgroup of the first process moved: that of the processes born in the cgroup of the VM
	home string
}

// podCgroupPath returns the directory of the cgroup of a pod, from its CgroupParent: a systemd slice
// (kubepods-besteffort-pod<uid>.slice, in kubepods.slice/kubepods-besteffort.slice) or a cgroupfs path.
func podCgroupPath(parent string) string {
	if !strings.HasSuffix(parent, ".slice") || strings.Contains(parent, "/") {
		return filepath.Join(cgroupRoot, parent)
	}
	parts := strings.Split(strings.TrimSuffix(parent, ".slice"), "-")
	dirs := []string{cgroupRoot}
	for i := range parts {
		dirs = append(dirs, strings.Join(parts[:i+1], "-")+".slice")
	}
	return filepath.Join(dirs...)
}

// isVMProcess tells whether a process belongs to a VM: FIRECRACKER_VM_ID=<vmID> in its environment, or --id <vmID>
// in its command line (the firecracker VMM).
func isVMProcess(pid int, vmID string) bool {
	for _, file := range []struct {
		name   string
		needle string
	}{{"environ", "\x00" + vmIDEnv + "=" + vmID + "\x00"}, {"cmdline", "\x00--id\x00" + vmID + "\x00"}} {
		// gone, or a kernel thread: nothing to read
		data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), file.name))
		if err == nil && bytes.Contains(append(append([]byte{0}, data...), 0), []byte(file.needle)) {
			return true
		}
	}
	return false
}

// allPIDs returns every process of /proc.
func allPIDs() ([]int, error) {
	entries, err := os.ReadDir(procRoot)
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

// cgroupPIDs returns the processes of a cgroup.
func cgroupPIDs(cgroup string) ([]int, error) {
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

// vmPIDs returns the processes of a VM.
func vmPIDs(vmID string) ([]int, error) {
	all, err := allPIDs()
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, pid := range all {
		if isVMProcess(pid, vmID) {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

var fccd struct {
	sync.Mutex
	cgroup string
}

// fccdCgroup returns the cgroup of the firecracker-containerd daemon, where the processes of the VMs start; "" when
// it is not found.
func fccdCgroup() string {
	fccd.Lock()
	defer fccd.Unlock()
	if fccd.cgroup != "" {
		if _, err := os.Stat(filepath.Join(fccd.cgroup, "cgroup.procs")); err == nil {
			return fccd.cgroup
		}
	}
	fccd.cgroup = ""
	pids, err := allPIDs()
	if err != nil {
		return ""
	}
	for _, pid := range pids {
		comm, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
		if err == nil && strings.TrimSpace(string(comm)) == fccdComm {
			if cgroup, err := processCgroup(pid); err == nil {
				fccd.cgroup = cgroup
			}
			break
		}
	}
	return fccd.cgroup
}

// processCgroup returns the cgroup v2 directory of a process.
func processCgroup(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(cgroupRoot, rel), nil
		}
	}
	return "", fmt.Errorf("process %d has no cgroup v2", pid)
}

func writePID(cgroup string, pid int) error {
	return os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
}

// newVMCgroup creates <cgroup of the pod>/vhive-vm-<vmID>, empty.
func newVMCgroup(vmID, cgroupParent string) (*vmCgroup, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return nil, errors.New("cgroup v2 is not mounted")
	}
	if cgroupParent == "" {
		return nil, errors.New("the pod has no cgroup parent")
	}
	pod := podCgroupPath(cgroupParent)
	if _, err := os.Stat(pod); err != nil {
		return nil, fmt.Errorf("no cgroup for the pod: %w", err)
	}
	cg := &vmCgroup{path: filepath.Join(pod, vmCgroupPrefix+vmID), origins: make(map[int]string)}
	if err := os.Mkdir(cg.path, 0o755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	return cg, nil
}

// adopt moves a process to the cgroup of the VM.
func (cg *vmCgroup) adopt(pid int) error {
	origin, err := processCgroup(pid)
	if err != nil || origin == cg.path {
		return nil // gone, or already there
	}
	if err := writePID(cg.path, pid); err != nil {
		return fmt.Errorf("failed to move process %d to %s: %w", pid, cg.path, err)
	}
	cg.origins[pid] = origin
	if cg.home == "" {
		cg.home = origin
	}
	return nil
}

// moveVMToPod moves the processes of a VM, already up, to <cgroup of its pod>/vhive-vm-<vmID>.
func moveVMToPod(vmID, cgroupParent string) (*vmCgroup, error) {
	cg, err := newVMCgroup(vmID, cgroupParent)
	if err != nil {
		return nil, err
	}
	pids, err := vmPIDs(vmID)
	if err != nil || len(pids) == 0 {
		_ = cg.release()
		return nil, fmt.Errorf("no process of VM %s", vmID)
	}
	for _, pid := range pids {
		if err := cg.adopt(pid); err != nil {
			_ = cg.release()
			return nil, err
		}
	}
	return cg, nil
}

// vmWatch moves the processes of a VM to its cgroup as soon as they appear, while the VM is created or loaded.
type vmWatch struct {
	vmID    string
	cg      *vmCgroup
	err     error
	done    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// watchVM starts to watch the creation of a VM: its processes go to <cgroup of its pod>/vhive-vm-<vmID> as soon as
// they appear in the cgroup of firecracker-containerd (where they start), checked every watchPeriod.
func watchVM(vmID, cgroupParent string) *vmWatch {
	w := &vmWatch{vmID: vmID, done: make(chan struct{}), stopped: make(chan struct{})}
	if w.cg, w.err = newVMCgroup(vmID, cgroupParent); w.err != nil {
		close(w.stopped)
		return w
	}
	go w.run(fccdCgroup())
	return w
}

func (w *vmWatch) run(source string) {
	defer close(w.stopped)
	checks := make(map[int]int)
	period := watchPeriod
	if source == "" {
		period = 4 * watchPeriod // all of /proc: less often
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		w.sweep(source, checks)
		select {
		case <-w.done:
			// The VM is up: its processes that were not seen in the cgroup of firecracker-containerd.
			w.sweep("", checks)
			return
		case <-ticker.C:
		}
	}
}

// sweep moves the processes of the VM among those of a cgroup (all of /proc for "") checked less than watchChecks
// times.
func (w *vmWatch) sweep(source string, checks map[int]int) {
	var pids []int
	var err error
	if source == "" {
		pids, err = allPIDs()
	} else {
		pids, err = cgroupPIDs(source)
	}
	if err != nil {
		return
	}
	for _, pid := range pids {
		if checks[pid] >= watchChecks {
			continue
		}
		checks[pid]++
		if isVMProcess(pid, w.vmID) {
			checks[pid] = watchChecks
			if err := w.cg.adopt(pid); err != nil {
				log.WithError(err).WithField("vmID", w.vmID).Warn("a process of the VM stays out of the cgroup of its pod")
			}
		}
	}
}

// stop ends the watch, once the VM is up or failed.
func (w *vmWatch) stop() {
	w.once.Do(func() {
		if w.cg != nil {
			close(w.done)
		}
	})
	<-w.stopped
}

// result returns the cgroup of the VM, once the watch is stopped: an error when no process of the VM was moved
// (its cgroup is then deleted).
func (w *vmWatch) result() (*vmCgroup, error) {
	if w.err != nil {
		return nil, w.err
	}
	if len(w.cg.origins) == 0 {
		_ = w.cg.release()
		return nil, fmt.Errorf("no process of VM %s was found", w.vmID)
	}
	return w.cg, nil
}

// release moves the processes of the VM back to their cgroups (those born in the cgroup of the VM to the one of the
// first process moved, and to the root cgroup when theirs is gone) and deletes the cgroup of the VM, so that the
// cgroup of its pod can be deleted.
func (cg *vmCgroup) release() error {
	if procs, err := os.ReadFile(filepath.Join(cg.path, "cgroup.procs")); err == nil {
		for _, field := range strings.Fields(string(procs)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				continue
			}
			origin, ok := cg.origins[pid]
			if !ok {
				origin = cg.home
			}
			if origin == "" || writePID(origin, pid) != nil {
				_ = writePID(cgroupRoot, pid)
			}
		}
	}
	if err := removeCgroup(cg.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
