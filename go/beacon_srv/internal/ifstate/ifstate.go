// Copyright 2019 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ifstate

import (
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	// DefaultKeepaliveInterval is the default time between sending IFID
	// keepalive packets to the neighbor.
	DefaultKeepaliveInterval = time.Second
	// DefaultKeepaliveTimeout specifies the default for how long an interface
	// can receive no IFID keepalive packets until it is considered expired.
	DefaultKeepaliveTimeout = 3 * DefaultKeepaliveInterval
)

const (
	// Inactive indicates that the interface has not been activated or
	// expired yet.
	Inactive State = "Inactive"
	// Active indicates that the interface is active.
	Active State = "Active"
	// Expired indicates that the interface is expired.
	Expired State = "Expired"
	// Revoked indicates that the interface is revoked.
	Revoked State = "Revoked"
)

// State is the state of an interface.
type State string

// Config enables configuration of the interfaces.
type Config struct {
	// KeepaliveTimeout specifies for how long an interface can receive no
	// IFID keepalive packets until it is considered expired.
	KeepaliveTimeout time.Duration
}

// InitDefaults initializes the config fields that are not set to the
// default values.
func (c *Config) InitDefaults() {
	if c.KeepaliveTimeout == 0 {
		c.KeepaliveTimeout = DefaultKeepaliveTimeout
	}
}

// Interfaces keeps track of all interfaces of the AS.
type Interfaces struct {
	mu    sync.RWMutex
	intfs map[common.IFIDType]*Interface
	cfg   Config
}

// NewInterfaces initializes the the interfaces with the provided interface info map.
func NewInterfaces(ifInfomap topology.IfInfoMap, cfg Config) *Interfaces {
	intfs := &Interfaces{
		cfg: cfg,
	}
	intfs.cfg.InitDefaults()
	intfs.Update(ifInfomap)
	return intfs
}

// Update updates the interface mapping. Interfaces no longer present in
// the topology are removed. The state of existing interfaces is preserved.
// New interfaces are added as inactive.
func (intfs *Interfaces) Update(ifInfomap topology.IfInfoMap) {
	intfs.mu.Lock()
	defer intfs.mu.Unlock()
	m := make(map[common.IFIDType]*Interface, len(intfs.intfs))
	for ifid, info := range ifInfomap {
		if intf, ok := intfs.intfs[ifid]; ok {
			intf.updateTopoInfo(info)
			m[ifid] = intf
		} else {
			m[ifid] = &Interface{
				topoInfo:     info,
				state:        Inactive,
				lastActivate: time.Now(),
				cfg:          intfs.cfg,
			}
		}
	}
	intfs.intfs = m
}

// Reset resets all interface states to inactive. This should be called
// by the beacon server if it is elected leader.
func (intfs *Interfaces) Reset() {
	intfs.mu.RLock()
	defer intfs.mu.RUnlock()
	for _, intf := range intfs.intfs {
		intf.reset()
	}
}

// All returns a copy of the map from interface id to interface.
func (intfs *Interfaces) All() map[common.IFIDType]*Interface {
	intfs.mu.RLock()
	defer intfs.mu.RUnlock()
	res := make(map[common.IFIDType]*Interface, len(intfs.intfs))
	for ifid, intf := range intfs.intfs {
		res[ifid] = intf
	}
	return res
}

// Get returns the interface for the specified id, or nil if not present.
func (intfs *Interfaces) Get(ifid common.IFIDType) *Interface {
	intfs.mu.RLock()
	defer intfs.mu.RUnlock()
	return intfs.intfs[ifid]
}

// Interface keeps track of the interface state.
type Interface struct {
	mu           sync.RWMutex
	topoInfo     topology.IFInfo
	state        State
	revocation   *path_mgmt.SignedRevInfo
	lastActivate time.Time
	cfg          Config
}

// Activate activates the interface the keep alive is received from when
// necessary, and sets the remote interface id. The return value indicates
// the previous state of the interface.
func (intf *Interface) Activate(remote common.IFIDType) State {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	prev := intf.state
	intf.state = Active
	intf.lastActivate = time.Now()
	intf.topoInfo.RemoteIFID = remote
	intf.revocation = nil
	return prev
}

// Expire checks whether the interface has not been activated for a certain
// amount of time. If that is the case and the current state is inactive or
// active, the state changes to Expired. The return value indicates,
// whether the state is expired or revoked when the call returns.
func (intf *Interface) Expire() bool {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	if intf.state == Expired || intf.state == Revoked {
		return true
	}
	if time.Now().Sub(intf.lastActivate) > intf.cfg.KeepaliveTimeout {
		intf.state = Expired
		return true
	}
	return false
}

// Revoke changes the state of the interface to revoked and updates the
// revocation, unless the current state is active. In that case, the
// interface has been activated in the meantime and should not be revoked.
// This is indicated through an error.
func (intf *Interface) Revoke(rev *path_mgmt.SignedRevInfo) error {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	if intf.state == Active {
		return common.NewBasicError("Interface activated in the meantime", nil)
	}
	intf.state = Revoked
	intf.revocation = rev
	return nil
}

// Revocation returns the revocation.
func (intf *Interface) Revocation() *path_mgmt.SignedRevInfo {
	intf.mu.RLock()
	defer intf.mu.RUnlock()
	return intf.revocation
}

// TopoInfo returns the topology information.
func (intf *Interface) TopoInfo() topology.IFInfo {
	intf.mu.RLock()
	defer intf.mu.RUnlock()
	return intf.topoInfo
}

// State returns the current state of the interface.
func (intf *Interface) State() State {
	intf.mu.RLock()
	defer intf.mu.RUnlock()
	return intf.state
}

func (intf *Interface) reset() {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	intf.state = Inactive
	intf.revocation = nil
	// Set the starting point for the timeout interval.
	intf.lastActivate = time.Now()
}

func (intf *Interface) updateTopoInfo(topoInfo topology.IFInfo) {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	// Keep remote topo info.
	topoInfo.RemoteIFID = intf.topoInfo.RemoteIFID
	intf.topoInfo = topoInfo
}
