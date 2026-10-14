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

package unikernel

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vhive-serverless/vhive/cri/podcgroup"
)

// The configuration file of firecracker (--config-file): the VM boots without its API.
type fcConfig struct {
	BootSource        fcBootSource  `json:"boot-source"`
	Drives            []fcDrive     `json:"drives"`
	MachineConfig     fcMachine     `json:"machine-config"`
	NetworkInterfaces []fcInterface `json:"network-interfaces"`
}

type fcBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	InitrdPath      string `json:"initrd_path,omitempty"`
	BootArgs        string `json:"boot_args,omitempty"`
}

type fcDrive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type fcMachine struct {
	VCPUCount  int `json:"vcpu_count"`
	MemSizeMiB int `json:"mem_size_mib"`
}

type fcInterface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac"`
	HostDevName string `json:"host_dev_name"`
}

// firecrackerConfig returns the configuration of firecracker for a VM of the image, with a network interface on the
// tap device when there is one.
func firecrackerConfig(img *Image, tap, mac string) ([]byte, error) {
	cfg := fcConfig{
		BootSource:        fcBootSource{KernelImagePath: img.Kernel, InitrdPath: img.Initrd, BootArgs: img.BootArgs},
		Drives:            []fcDrive{},
		MachineConfig:     fcMachine{VCPUCount: img.VCPUs, MemSizeMiB: img.MemoryMiB},
		NetworkInterfaces: []fcInterface{},
	}
	for i, d := range img.Drives {
		cfg.Drives = append(cfg.Drives, fcDrive{DriveID: fmt.Sprintf("drive%d", i), PathOnHost: d.Path, IsReadOnly: d.ReadOnly})
	}
	if tap != "" {
		cfg.NetworkInterfaces = append(cfg.NetworkInterfaces, fcInterface{IfaceID: "eth0", GuestMAC: mac, HostDevName: tap})
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// vm is a firecracker process booting a unikernel.
type vm struct {
	id  string
	dir string
	cmd *exec.Cmd
	// closed when the process exited
	exited chan struct{}
	// the cgroup of the VM in the cgroup of its pod, nil when it runs out of it
	cgroup *podcgroup.Cgroup
}

// vmSpec is what a VM needs to start: a network namespace with a tap device (none: no network) and a cgroup to start
// in (nil: the one of vHive).
type vmSpec struct {
	id          string
	image       *Image
	dir         string
	firecracker string
	netns       string
	tap         string
	mac         string
	cgroup      *podcgroup.Cgroup
}

// startVM starts firecracker in the network namespace and the cgroup of the VM: it is born in the cgroup, its boot is
// accounted for. Its console and its log go to <dir>/console.log.
func startVM(spec vmSpec) (*vm, error) {
	if err := os.MkdirAll(spec.dir, 0o755); err != nil {
		return nil, err
	}
	cfg, err := firecrackerConfig(spec.image, spec.tap, spec.mac)
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(spec.dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		return nil, err
	}
	console, err := os.Create(filepath.Join(spec.dir, "console.log"))
	if err != nil {
		return nil, err
	}
	defer console.Close()

	args := []string{spec.firecracker, "--no-api", "--config-file", cfgPath, "--id", spec.id, "--level", "Warning"}
	if spec.netns != "" {
		// nsenter execs firecracker: same process, in the namespace of the VM
		args = append([]string{"nsenter", "--net=" + spec.netns, "--"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = console, console
	// its own process group: the signals of vHive are not for it
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if spec.cgroup != nil {
		dir, err := os.Open(spec.cgroup.Path)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = int(dir.Fd())
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start firecracker: %w", err)
	}
	v := &vm{id: spec.id, dir: spec.dir, cmd: cmd, exited: make(chan struct{}), cgroup: spec.cgroup}
	go func() {
		_ = cmd.Wait()
		close(v.exited)
	}()
	return v, nil
}

// stop kills firecracker (a unikernel has nothing to save) and waits for it, at most the timeout.
func (v *vm) stop(timeout time.Duration) error {
	select {
	case <-v.exited:
		return nil
	default:
	}
	if err := v.cmd.Process.Kill(); err != nil {
		return err
	}
	select {
	case <-v.exited:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("firecracker of VM %s still runs after %v", v.id, timeout)
	}
}
