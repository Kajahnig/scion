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
	"fmt"
	"reflect"
	"sync"
	"time"

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

		isAck, filterErr := c.filter(pkt, ov)

		if filterErr != nil || isAck {
			return filterErr
		}
	}

	return err
}

func (c *FilterPacketConn) filter(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) (bool, error) {

	for _, f := range c.packetFilters {
		result, err := (*f).FilterPacket(pkt)
		switch result {
		case FilterError:
			log.Debug(fmt.Sprintf("%v encountered an error on packet from source IA %v",
				reflect.TypeOf(*f), pkt.Source.IA.String()), err)
			return false, err
		case FilterAccept:
			log.Debug(fmt.Sprintf("%v accepted packet from source IA %v",
				reflect.TypeOf(*f), pkt.Source.IA.String()))
		case FilterDrop:
			if pkt.L4Header.L4Type() == common.L4SCMP {
				//Drop SCMP packets without sending an SCMP back
				log.Debug(fmt.Sprintf("%v dropped SCMP packet from IA %v",
					reflect.TypeOf(*f), pkt.Source.IA.String()))
				return false, nil
			}
			typeOfFilter := reflect.TypeOf(*f)
			log.Debug(fmt.Sprintf("%v decides to drop packet and send SCMP message to %v",
				typeOfFilter, pkt.Source.IA.String()))
			return false, c.returnSCMPErrorMsg(pkt, (*f).SCMPError(), ov, typeOfFilter)
		}
	}
	log.Debug(fmt.Sprintf("Packet from %v passed all filters", pkt.Source.IA.String()))
	return true, nil
}

func (c *FilterPacketConn) returnSCMPErrorMsg(receivedPkt *snet.SCIONPacket,
	scmpCT scmp.ClassType, ov *overlay.OverlayAddr, typeOfFilter reflect.Type) error {

	var path *spath.Path

	if receivedPkt.Path != nil {
		path = receivedPkt.Path.Copy()
		err := path.Reverse()
		if err != nil {
			return err
		}
	}

	var info scmp.InfoString = "Packet failed to pass filter"

	pld := scmp.PldFromQuotes(scmpCT, info, common.L4UDP, MyQuoteFunc(receivedPkt))

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
			L4Header: scmp.NewHdr(scmpCT, pld.Len()),
			Payload:  pld,
		},
	}
	log.Debug(fmt.Sprintf("Writing SCMP error message %v from %v",
		scmpCT.String(), typeOfFilter))
	return c.writeWithLock(SCMPErrorPkt, ov)
}

// GetRaw returns slices of the underlying buffer corresponding to part of the
// packet identified by the blk argument. This is used, for example, by SCMP to
// quote parts of the packet in an error response.
func MyQuoteFunc(receivedPkt *snet.SCIONPacket) func(blk scmp.RawBlock) common.RawBytes {
	return func(blk scmp.RawBlock) common.RawBytes {
		switch blk {
		case scmp.RawL4Hdr:
			p := make(common.RawBytes, receivedPkt.L4Header.L4Len())
			receivedPkt.L4Header.Write(p)
			return p
		}
		return nil
	}
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
