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
// They are moved to a cgroup of their own in the cgroup of the pod, <pod cgroup>/vhive-vm-<vmID> (see podcgroup),
// as soon as they appear while the VM is created (watchVM): the pod accounts for the VM, its boot included, as for a
// container.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vhive-serverless/vhive/cri/podcgroup"
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

// isVMProcess tells whether a process belongs to a VM: FIRECRACKER_VM_ID=<vmID> in its environment, or --id <vmID>
// in its command line (the firecracker VMM).
func isVMProcess(pid int, vmID string) bool {
	for _, file := range []struct {
		name   string
		needle string
	}{{"environ", "\x00" + vmIDEnv + "=" + vmID + "\x00"}, {"cmdline", "\x00--id\x00" + vmID + "\x00"}} {
		// gone, or a kernel thread: nothing to read
		data, err := os.ReadFile(filepath.Join(podcgroup.Proc, strconv.Itoa(pid), file.name))
		if err == nil && bytes.Contains(append(append([]byte{0}, data...), 0), []byte(file.needle)) {
			return true
		}
	}
	return false
}

// vmPIDs returns the processes of a VM.
func vmPIDs(vmID string) ([]int, error) {
	all, err := podcgroup.AllPIDs()
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
	pids, err := podcgroup.AllPIDs()
	if err != nil {
		return ""
	}
	for _, pid := range pids {
		comm, err := os.ReadFile(filepath.Join(podcgroup.Proc, strconv.Itoa(pid), "comm"))
		if err == nil && strings.TrimSpace(string(comm)) == fccdComm {
			if cgroup, err := podcgroup.ProcessCgroup(pid); err == nil {
				fccd.cgroup = cgroup
			}
			break
		}
	}
	return fccd.cgroup
}

// moveVMToPod moves the processes of a VM, already up, to <cgroup of its pod>/vhive-vm-<vmID>.
func moveVMToPod(vmID, cgroupParent string) (*podcgroup.Cgroup, error) {
	cg, err := podcgroup.New(vmCgroupPrefix+vmID, cgroupParent)
	if err != nil {
		return nil, err
	}
	pids, err := vmPIDs(vmID)
	if err != nil || len(pids) == 0 {
		_ = cg.Release()
		return nil, fmt.Errorf("no process of VM %s", vmID)
	}
	for _, pid := range pids {
		if err := cg.Adopt(pid); err != nil {
			_ = cg.Release()
			return nil, err
		}
	}
	return cg, nil
}

// vmWatch moves the processes of a VM to its cgroup as soon as they appear, while the VM is created or loaded.
type vmWatch struct {
	vmID    string
	cg      *podcgroup.Cgroup
	err     error
	done    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// watchVM starts to watch the creation of a VM: its processes go to <cgroup of its pod>/vhive-vm-<vmID> as soon as
// they appear in the cgroup of firecracker-containerd (where they start), checked every watchPeriod.
func watchVM(vmID, cgroupParent string) *vmWatch {
	w := &vmWatch{vmID: vmID, done: make(chan struct{}), stopped: make(chan struct{})}
	if w.cg, w.err = podcgroup.New(vmCgroupPrefix+vmID, cgroupParent); w.err != nil {
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
		pids, err = podcgroup.AllPIDs()
	} else {
		pids, err = podcgroup.PIDs(source)
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
			if err := w.cg.Adopt(pid); err != nil {
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
func (w *vmWatch) result() (*podcgroup.Cgroup, error) {
	if w.err != nil {
		return nil, w.err
	}
	if w.cg.Adopted() == 0 {
		_ = w.cg.Release()
		return nil, fmt.Errorf("no process of VM %s was found", w.vmID)
	}
	return w.cg, nil
}
