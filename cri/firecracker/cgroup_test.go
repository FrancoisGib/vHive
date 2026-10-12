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

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPodCgroupPath(t *testing.T) {
	require.Equal(t,
		"/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1a2b_3c4d.slice",
		podCgroupPath("kubepods-besteffort-pod1a2b_3c4d.slice"))
	require.Equal(t, "/sys/fs/cgroup/kubepods.slice/kubepods-pod1a2b.slice", podCgroupPath("kubepods-pod1a2b.slice"))
	require.Equal(t, "/sys/fs/cgroup/kubepods/besteffort/pod1a2b", podCgroupPath("/kubepods/besteffort/pod1a2b"))
}

// A fake /proc and cgroup tree: the processes of the VM are found by their environment or their command line, moved
// to the cgroup of the pod, then back to their cgroup.
func TestMoveVMToPod(t *testing.T) {
	root := t.TempDir()
	cgroupRoot, procRoot = filepath.Join(root, "cgroup"), filepath.Join(root, "proc")
	defer func() { cgroupRoot, procRoot = "/sys/fs/cgroup", "/proc" }()

	pod := filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-poduid.slice")
	fccd := filepath.Join(cgroupRoot, "system.slice", "fccd.scope")
	for _, dir := range []string{pod, fccd} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(cgroupRoot, "cgroup.controllers"), []byte("cpu memory"), 0o644))

	processes := map[int][2]string{ // environ, cmdline
		10: {"PATH=/bin\x00FIRECRACKER_VM_ID=1-abc\x00", "containerd-shim-aws-firecracker\x00-namespace\x00x\x00"},
		11: {"PATH=/bin\x00", "firecracker\x00--api-sock\x00fc.sock\x00--id\x001-abc\x00"},
		12: {"FIRECRACKER_VM_ID=2-def\x00", "firecracker\x00--id\x002-def\x00"},
	}
	for pid, files := range processes {
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "environ"), []byte(files[0]), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cmdline"), []byte(files[1]), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/system.slice/fccd.scope\n"), 0o644))
	}

	pids, err := vmPIDs("1-abc")
	require.NoError(t, err)
	require.ElementsMatch(t, []int{10, 11}, pids)

	cg, err := moveVMToPod("1-abc", "kubepods-besteffort-poduid.slice")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(pod, "vhive-vm-1-abc"), cg.path)
	require.Equal(t, map[int]string{10: fccd, 11: fccd}, cg.origins)

	// back to their cgroup: release reads the processes in the cgroup of the VM (all of them in a real cgroup.procs)
	removeCgroup = os.RemoveAll // a fake cgroup directory has real files
	defer func() { removeCgroup = os.Remove }()
	require.NoError(t, os.WriteFile(filepath.Join(cg.path, "cgroup.procs"), []byte("10\n11\n"), 0o644))
	require.NoError(t, cg.release())
	require.NoDirExists(t, cg.path)
	data, err := os.ReadFile(filepath.Join(fccd, "cgroup.procs"))
	require.NoError(t, err)
	require.Equal(t, "11", string(data)) // the last process written back
}

// While a VM is created, its processes are moved as they appear in the cgroup of firecracker-containerd: the shim,
// first a copy of firecracker-containerd until its exec, then the firecracker VMM.
func TestWatchVM(t *testing.T) {
	root := t.TempDir()
	cgroupRoot, procRoot = filepath.Join(root, "cgroup"), filepath.Join(root, "proc")
	removeCgroup = os.RemoveAll // a fake cgroup directory has real files
	defer func() { cgroupRoot, procRoot, removeCgroup = "/sys/fs/cgroup", "/proc", os.Remove }()

	pod := filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-poduid.slice")
	fccdDir := filepath.Join(cgroupRoot, "system.slice", "fccd.scope")
	for _, dir := range []string{pod, fccdDir} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(cgroupRoot, "cgroup.controllers"), []byte("cpu memory"), 0o644))
	procs := []string{"1"}
	process := func(pid int, comm, environ, cmdline string) {
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		for name, content := range map[string]string{"comm": comm + "\n", "environ": environ, "cmdline": cmdline, "cgroup": "0::/system.slice/fccd.scope\n"} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
		}
	}
	appear := func(pid int) {
		procs = append(procs, strconv.Itoa(pid))
		require.NoError(t, os.WriteFile(filepath.Join(fccdDir, "cgroup.procs"), []byte(strings.Join(procs, "\n")), 0o644))
	}
	process(1, "firecracker-con", "PATH=/bin\x00", "firecracker-containerd\x00")
	appear(1)

	w := watchVM("1-abc", "kubepods-besteffort-poduid.slice")
	process(10, "firecracker-con", "PATH=/bin\x00", "firecracker-containerd\x00") // the shim before its exec
	appear(10)
	time.Sleep(4 * watchPeriod)
	process(10, "containerd-shim", "PATH=/bin\x00FIRECRACKER_VM_ID=1-abc\x00", "containerd-shim-aws-firecracker\x00")
	time.Sleep(4 * watchPeriod)
	process(11, "firecracker", "PATH=/bin\x00", "firecracker\x00--id\x001-abc\x00")
	appear(11)
	process(12, "firecracker", "FIRECRACKER_VM_ID=2-def\x00", "firecracker\x00--id\x002-def\x00") // another VM
	appear(12)
	time.Sleep(4 * watchPeriod)
	w.stop()

	cg, err := w.result()
	require.NoError(t, err)
	require.Equal(t, map[int]string{10: fccdDir, 11: fccdDir}, cg.origins)
	require.Equal(t, fccdDir, cg.home)
}

// A VM whose processes are never found: no cgroup is kept.
func TestWatchVMWithoutProcess(t *testing.T) {
	root := t.TempDir()
	cgroupRoot, procRoot = filepath.Join(root, "cgroup"), filepath.Join(root, "proc")
	removeCgroup = os.RemoveAll
	defer func() { cgroupRoot, procRoot, removeCgroup = "/sys/fs/cgroup", "/proc", os.Remove }()

	pod := filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-pod1.slice")
	require.NoError(t, os.MkdirAll(pod, 0o755))
	require.NoError(t, os.MkdirAll(procRoot, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(cgroupRoot, "cgroup.controllers"), []byte("cpu"), 0o644))

	w := watchVM("3-ghi", "kubepods-pod1.slice")
	w.stop()
	_, err := w.result()
	require.Error(t, err)
	require.NoDirExists(t, filepath.Join(pod, "vhive-vm-3-ghi"))

	// without cgroup v2, nothing is watched
	require.NoError(t, os.Remove(filepath.Join(cgroupRoot, "cgroup.controllers")))
	w = watchVM("4-jkl", "kubepods-pod1.slice")
	w.stop()
	_, err = w.result()
	require.Error(t, err)
}
