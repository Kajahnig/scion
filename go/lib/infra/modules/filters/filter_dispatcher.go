// Copyright 2019 ETH Zurich
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

package filters

import (
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var _ snet.PacketDispatcherService = (*FilteringPacketDispatcher)(nil)

type FilteringPacketDispatcher struct {
	snet.PacketDispatcherService
	packetFilters []*PacketFilter
}

func NewFilteringPacketDispatcher(packetFilters []*PacketFilter) *FilteringPacketDispatcher {
	return &FilteringPacketDispatcher{
		PacketDispatcherService: snet.NewDefaultPacketDispatcherService(
			reliable.NewDispatcherService(""),
		),
		packetFilters: packetFilters,
	}
}

func (d *FilteringPacketDispatcher) RegisterTimeout(ia addr.IA,
	public *addr.AppAddr, bind *overlay.OverlayAddr, svc addr.HostSVC,
	timeout time.Duration) (snet.PacketConn, uint16, error) {

	conn, port, err := d.PacketDispatcherService.RegisterTimeout(ia, public, bind, svc, timeout)
	if err != nil {
		return nil, 0, err
	}
	return NewFilterPacketConn(conn, d.packetFilters), port, err
}
