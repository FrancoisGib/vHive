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
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// imageFile describes a unikernel image, in its directory <images>/<name>/: its kernel, an initrd or drives, its boot
// arguments and the size of its VMs. The files it names are relative to the directory.
const imageFile = "unikernel.json"

// Image is a unikernel image, with the absolute paths of its files.
type Image struct {
	Kernel    string  `json:"kernel"`
	Initrd    string  `json:"initrd,omitempty"`
	Drives    []Drive `json:"drives,omitempty"`
	BootArgs  string  `json:"boot_args,omitempty"`
	VCPUs     int     `json:"vcpus"`
	MemoryMiB int     `json:"memory_mib"`
}

// Drive is a disk of the VM. A drive shared by the VMs of an image must be read-only.
type Drive struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only"`
}

// loadImage reads <dir>/unikernel.json.
func loadImage(dir string) (*Image, error) {
	data, err := os.ReadFile(filepath.Join(dir, imageFile))
	if err != nil {
		return nil, fmt.Errorf("no unikernel image in %s: %w", dir, err)
	}
	// by default, those of firecracker-containerd (runtime/helpers.go)
	img := &Image{VCPUs: 1, MemoryMiB: 128}
	if err := json.Unmarshal(data, img); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", filepath.Join(dir, imageFile), err)
	}
	if img.Kernel == "" {
		return nil, errors.New("the unikernel image has no kernel")
	}
	if img.VCPUs < 1 || img.MemoryMiB < 1 {
		return nil, errors.New("the unikernel image needs at least one vCPU and some memory")
	}
	resolve := func(path string) (string, error) {
		if path == "" {
			return "", nil
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		if _, err := os.Stat(path); err != nil {
			return "", err
		}
		return path, nil
	}
	if img.Kernel, err = resolve(img.Kernel); err != nil {
		return nil, err
	}
	if img.Initrd, err = resolve(img.Initrd); err != nil {
		return nil, err
	}
	for i := range img.Drives {
		if img.Drives[i].Path, err = resolve(img.Drives[i].Path); err != nil {
			return nil, err
		}
	}
	return img, nil
}
