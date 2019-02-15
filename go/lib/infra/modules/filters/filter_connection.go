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
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
)

//var _ snet.RawSCIONConn = (*FilteringRawSCIONConn)(nil) TODO: uncomment when interface available

type FilteringRawSCIONConn struct {
	conn          *snet.RawSCIONConn
	packetFilters []*PacketFilter

	mtx             sync.Mutex
	SCMPWriteBuffer common.RawBytes
}

func NewFilteringRawScionConn(conn *snet.RawSCIONConn, packetFilters []*PacketFilter) *snet.RawSCIONConn {
	filter := &FilteringRawSCIONConn{
		conn:            conn,
		SCMPWriteBuffer: make(common.RawBytes, common.MaxMTU),
		packetFilters:   append([]*PacketFilter{}, packetFilters...),
	}
	return filter.conn //TODO: return the whole filter when interface available
}

func (c *FilteringRawSCIONConn) Close() error {
	return c.conn.Close()
}

func (c *FilteringRawSCIONConn) ReadFrom(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {

	err := c.conn.ReadFrom(pkt, ov)

	for ; err == nil; err = c.conn.ReadFrom(pkt, ov) {

		isAck, filterErr := c.filter(pkt)

		if filterErr != nil || isAck {
			return filterErr
		}
	}

	return err
}

func (c *FilteringRawSCIONConn) filter(pkt *snet.SCIONPacket) (bool, error) {

	for _, f := range c.packetFilters {
		result, err := (*f).FilterPacket(pkt)
		switch result {
		case FilterError:
			return false, err
		case FilterAccept:
			continue
		case FilterDrop:
			if pkt.L4Header.L4Type() == common.L4SCMP {
				//Drop SCMP packets without sending an SCMP back
				return false, nil
			}
			return false, c.returnSCMPErrorMsg(pkt, (*f).SCMPError())
		}
	}
	return true, nil
}

func (c *FilteringRawSCIONConn) returnSCMPErrorMsg(receivedPkt *snet.SCIONPacket, scmpCT scmp.ClassType) error {
	path := receivedPkt.Path.Copy()
	err := path.Reverse()

	if err != nil {
		return err
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

func (c *FilteringRawSCIONConn) WriteTo(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
	return c.writeWithLock(pkt, ov)
}

func (c *FilteringRawSCIONConn) writeWithLock(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.conn.WriteTo(pkt, ov)
}

func (c *FilteringRawSCIONConn) SetDeadline(d time.Time) error {
	return c.conn.SetDeadline(d)
}

func (c *FilteringRawSCIONConn) SetReadDeadline(d time.Time) error {
	return c.conn.SetReadDeadline(d)
}

func (c *FilteringRawSCIONConn) SetWriteDeadline(d time.Time) error {
	return c.conn.SetWriteDeadline(d)
}
