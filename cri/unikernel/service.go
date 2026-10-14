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

// Package unikernel runs the functions as unikernels booted by firecracker, without firecracker-containerd nor a
// guest OS: the user container of a function pod (a placeholder) comes with a microVM booting the unikernel image
// named by its GUEST_IMAGE (<images>/<name>/unikernel.json). Each VM has a network of its own (vHive's network
// manager: the guest is 172.16.0.2/24 behind 172.16.0.1 in its namespace, reachable from the host at a clone IP given
// to the queue-proxy of the pod) and runs in the cgroup of its pod, where firecracker is born.
package unikernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/vhive-serverless/vhive/cri"
	"github.com/vhive-serverless/vhive/cri/podcgroup"
	"github.com/vhive-serverless/vhive/networking"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	userContainerName = "user-container"
	queueProxyName    = "queue-proxy"
	guestIPEnv        = "GUEST_ADDR"
	guestPortEnv      = "GUEST_PORT"
	guestImageEnv     = "GUEST_IMAGE"
	vmVcpusEnv        = "VM_VCPUS"
	vmMemoryEnv       = "VM_MEMORY_MIB"
	vmCgroupPrefix    = "vhive-vm-"
	// a killed firecracker exits at once
	stopTimeout = 10 * time.Second
)

// Service is the CRI of the unikernels.
type Service struct {
	sync.Mutex

	stockRuntimeClient criapi.RuntimeServiceClient
	network            *networking.NetworkManager

	// the unikernel images (<images>/<name>/unikernel.json), the directories of the VMs, firecracker
	images, vms, firecracker string

	nextID uint64
	// the VM of each user container
	running map[string]*vm
	// the address of the VM of each pod, for its queue-proxy
	guests map[string]guest
}

type guest struct {
	ip, port string
}

// NewService returns the CRI of the unikernels: their images in `images`, the files of their VMs in `vms`.
func NewService(network *networking.NetworkManager, images, vms, firecracker string) (*Service, error) {
	stockRuntimeClient, err := cri.NewStockRuntimeServiceClient()
	if err != nil {
		log.WithError(err).Error("failed to create new stock runtime service client")
		return nil, err
	}
	if err := os.MkdirAll(vms, 0o755); err != nil {
		return nil, err
	}
	return &Service{
		stockRuntimeClient: stockRuntimeClient,
		network:            network,
		images:             images,
		vms:                vms,
		firecracker:        firecracker,
		running:            make(map[string]*vm),
		guests:             make(map[string]guest),
	}, nil
}

// CreateContainer starts a VM with the user container, gives its address to the queue-proxy, and passes the other
// containers to the stock runtime.
func (s *Service) CreateContainer(ctx context.Context, r *criapi.CreateContainerRequest) (*criapi.CreateContainerResponse, error) {
	switch r.GetConfig().GetMetadata().GetName() {
	case userContainerName:
		return s.createUserContainer(ctx, r)
	case queueProxyName:
		return s.createQueueProxy(ctx, r)
	default:
		return s.stockRuntimeClient.CreateContainer(ctx, r)
	}
}

func (s *Service) createUserContainer(ctx context.Context, r *criapi.CreateContainerRequest) (*criapi.CreateContainerResponse, error) {
	var (
		stockResp *criapi.CreateContainerResponse
		stockErr  error
		stockDone = make(chan struct{})
	)
	// the placeholder container, meanwhile
	go func() {
		defer close(stockDone)
		stockResp, stockErr = s.stockRuntimeClient.CreateContainer(ctx, r)
	}()

	v, ip, port, err := s.startVM(r)
	if err != nil {
		log.WithError(err).Error("failed to start the unikernel VM")
		<-stockDone
		return nil, err
	}
	s.Lock()
	s.guests[r.GetPodSandboxId()] = guest{ip: ip, port: port}
	s.Unlock()

	<-stockDone
	if stockErr != nil {
		log.WithError(stockErr).Error("failed to create the placeholder container")
		s.stopVM(v)
		return nil, stockErr
	}
	s.Lock()
	s.running[stockResp.GetContainerId()] = v
	s.Unlock()
	return stockResp, nil
}

// startVM starts the VM of a user container, in the cgroup of its pod, and returns its address.
func (s *Service) startVM(r *criapi.CreateContainerRequest) (*vm, string, string, error) {
	config := r.GetConfig()
	name, err := getEnvVal(guestImageEnv, config)
	if err != nil {
		return nil, "", "", err
	}
	port, err := getEnvVal(guestPortEnv, config)
	if err != nil {
		return nil, "", "", err
	}
	img, err := loadImage(filepath.Join(s.images, name))
	if err != nil {
		return nil, "", "", err
	}
	// the size of the VM: that of the function (VM_VCPUS, VM_MEMORY_MIB), else that of the image
	for _, size := range []struct {
		env   string
		image *int
	}{{vmVcpusEnv, &img.VCPUs}, {vmMemoryEnv, &img.MemoryMiB}} {
		if value, err := getEnvVal(size.env, config); err == nil {
			if n, err := strconv.Atoi(value); err == nil && n > 0 {
				*size.image = n
			}
		}
	}

	id := fmt.Sprintf("%d-%s", atomic.AddUint64(&s.nextID, 1), uuid.New().String()[:16])
	logger := log.WithFields(log.Fields{"vmID": id, "image": name})
	netCfg, err := s.network.CreateNetwork(id)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to create the network of the VM: %w", err)
	}
	cg, err := podcgroup.New(vmCgroupPrefix+id, r.GetSandboxConfig().GetLinux().GetCgroupParent())
	if err != nil {
		logger.WithError(err).Warn("the VM runs out of the cgroup of its pod")
		cg = nil
	}
	v, err := startVM(vmSpec{
		id:          id,
		image:       img,
		dir:         filepath.Join(s.vms, id),
		firecracker: s.firecracker,
		netns:       netCfg.GetNamespacePath(),
		tap:         netCfg.GetHostDevName(),
		mac:         netCfg.GetMacAddress(),
		cgroup:      cg,
	})
	if err != nil {
		if cg != nil {
			_ = cg.Release()
		}
		_ = s.network.RemoveNetwork(id)
		return nil, "", "", err
	}
	logger.Debug("unikernel VM started")
	return v, netCfg.GetCloneIP(), port, nil
}

func (s *Service) createQueueProxy(ctx context.Context, r *criapi.CreateContainerRequest) (*criapi.CreateContainerResponse, error) {
	s.Lock()
	g, ok := s.guests[r.GetPodSandboxId()]
	delete(s.guests, r.GetPodSandboxId())
	s.Unlock()
	if !ok {
		err := fmt.Errorf("no unikernel VM for pod %s", r.GetPodSandboxId())
		log.WithError(err).Error()
		return nil, err
	}
	r.Config.Envs = append(r.Config.Envs, &criapi.KeyValue{Key: guestIPEnv, Value: g.ip}, &criapi.KeyValue{Key: guestPortEnv, Value: g.port})
	return s.stockRuntimeClient.CreateContainer(ctx, r)
}

// RemoveContainer stops the VM of a user container before the stock runtime removes it: its cgroup is then empty,
// and the cgroup of its pod can be deleted.
func (s *Service) RemoveContainer(ctx context.Context, r *criapi.RemoveContainerRequest) (*criapi.RemoveContainerResponse, error) {
	s.Lock()
	v, ok := s.running[r.GetContainerId()]
	delete(s.running, r.GetContainerId())
	s.Unlock()
	if ok {
		s.stopVM(v)
	}
	return s.stockRuntimeClient.RemoveContainer(ctx, r)
}

// stopVM stops a VM and deletes its cgroup, its network and its files.
func (s *Service) stopVM(v *vm) {
	logger := log.WithField("vmID", v.id)
	if err := v.stop(stopTimeout); err != nil {
		logger.WithError(err).Error("failed to stop the unikernel VM")
	}
	if v.cgroup != nil {
		if err := v.cgroup.Release(); err != nil {
			logger.WithError(err).Warn("failed to delete the cgroup of the VM")
		}
	}
	if err := s.network.RemoveNetwork(v.id); err != nil {
		logger.WithError(err).Warn("failed to remove the network of the VM")
	}
	if err := os.RemoveAll(v.dir); err != nil {
		logger.WithError(err).Warn("failed to delete the files of the VM")
	}
}

func getEnvVal(key string, config *criapi.ContainerConfig) (string, error) {
	for _, kv := range config.GetEnvs() {
		if kv.GetKey() == key {
			return kv.GetValue(), nil
		}
	}
	return "", errors.New("no " + key + " in the environment of the user container")
}
