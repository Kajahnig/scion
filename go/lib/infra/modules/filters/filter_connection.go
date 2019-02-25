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
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

var _ snet.PacketConn = (*FilterPacketConn)(nil)

type FilterPacketConn struct {
	conn          snet.PacketConn
	packetFilters []*PacketFilter

	mtx             sync.Mutex
	SCMPWriteBuffer common.RawBytes
}

func NewFilterPacketConn(conn snet.PacketConn, packetFilters []*PacketFilter) *FilterPacketConn {
	return &FilterPacketConn{
		conn:            conn,
		SCMPWriteBuffer: make(common.RawBytes, common.MaxMTU),
		packetFilters:   append([]*PacketFilter{}, packetFilters...),
	}
}

func (c *FilterPacketConn) Close() error {
	return c.conn.Close()
}

func (c *FilterPacketConn) ReadFrom(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {

	err := c.conn.ReadFrom(pkt, ov)

	for ; err == nil; err = c.conn.ReadFrom(pkt, ov) {

		isAck, filterErr := c.filter(pkt)

		if filterErr != nil || isAck {
			return filterErr
		}
	}

	return err
}

func (c *FilterPacketConn) filter(pkt *snet.SCIONPacket) (bool, error) {

	for _, f := range c.packetFilters {
		result, err := (*f).FilterPacket(pkt)
		switch result {
		case FilterError:
			log.Debug("Filter encountered an error on packet from source IA "+pkt.Source.IA.String(), err)
			return false, err
		case FilterAccept:
			log.Debug("Filter accepted packet from source IA " + pkt.Source.IA.String())
		case FilterDrop:
			if pkt.L4Header.L4Type() == common.L4SCMP {
				//Drop SCMP packets without sending an SCMP back
				log.Debug("Filter dropped SCMP packet from IA " + pkt.Source.IA.String())
				return false, nil
			}
			log.Debug("Filter decides to drop packet and send SCMP message to " + pkt.Source.IA.String())
			return false, c.returnSCMPErrorMsg(pkt, (*f).SCMPError())
		}
	}
	log.Debug("Packet passed all filters. Source: " + pkt.Source.IA.String())
	return true, nil
}

func (c *FilterPacketConn) returnSCMPErrorMsg(receivedPkt *snet.SCIONPacket, scmpCT scmp.ClassType) error {
	var path *spath.Path

	if receivedPkt.Path != nil {
		path = receivedPkt.Path.Copy()
		err := path.Reverse()
		if err != nil {
			return err
		}
	}

	var info scmp.InfoString = "Packet failed to pass filter"
	scmpMeta := scmp.Meta{InfoLen: uint8(info.Len() / common.LineLen)}
	pld := make(common.RawBytes, scmp.MetaLen+info.Len())
	scmpMeta.Write(pld)
	info.Write(pld[scmp.MetaLen:])

	SCMPErrorPkt := &snet.SCIONPacket{
		Bytes: snet.Bytes(c.SCMPWriteBuffer),
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Destination: receivedPkt.Source,
			Source:      receivedPkt.Destination,
			Path:        path,
			Extensions: []common.Extension{
				&layers.ExtnSCMP{
					Error:    true,
					HopByHop: false,
				},
			},
			L4Header: scmp.NewHdr(scmpCT, len(pld)),
			Payload:  pld,
		},
	}
	overlayAddress, err := overlay.NewOverlayAddr(receivedPkt.Source.Host, addr.NewL4SCMPInfo())

	if err != nil {
		return err
	}
	return c.writeWithLock(SCMPErrorPkt, overlayAddress)
}

func (c *FilterPacketConn) WriteTo(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
	return c.writeWithLock(pkt, ov)
}

func (c *FilterPacketConn) writeWithLock(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.conn.WriteTo(pkt, ov)
}

func (c *FilterPacketConn) SetDeadline(d time.Time) error {
	return c.conn.SetDeadline(d)
}

func (c *FilterPacketConn) SetReadDeadline(d time.Time) error {
	return c.conn.SetReadDeadline(d)
}

func (c *FilterPacketConn) SetWriteDeadline(d time.Time) error {
	return c.conn.SetWriteDeadline(d)
}
