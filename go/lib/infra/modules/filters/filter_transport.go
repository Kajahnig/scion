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
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

var _ infra.Transport = (*FilterTransport)(nil)

// FilterTransport implements interface Transport by wrapping around a
// snet.Conn. The reliability of the underlying snet.Conn defines the
// semantics behind SendMsgTo and SendUnreliableMsgTo.
//
//TODO: the following lines were copied from packet_transport.go. If the net.PacketConn behaves differently
// from a snet.Conn, they need to be adapted.
//
// For PacketTransports running on top of UDP, both SendMsgTo and
// SendUnreliableMsgTo are unreliable.
//
// For PacketTransports running on top of UNIX domain socket with SOCK_DGRAM or
// Reliable socket, both SendMsgTo and SendUnreliableMsgTo guarantee reliable
// delivery to the other other end of the socket. Note that in this case, the
// reliability only extends to the guarantee that the message was not lost in
// transfer. It is not a guarantee that the server has read and processed the
// message.
type FilterTransport struct {
	conn snet.Conn
	// While conn is safe for use from multiple goroutines, deadlines are
	// global so it is not safe to enforce two at the same time. Thus, to
	// meet context deadlines we serialize access to the conn.
	writeLock *util.ChannelLock
	readLock  *util.ChannelLock
	//hook slice for filters that need to be applied to packets
	addrFilters []*AddrFilter
}

func NewFilterTransport(conn snet.Conn) *FilterTransport {
	return &FilterTransport{
		conn:        conn,
		writeLock:   util.NewChannelLock(),
		readLock:    util.NewChannelLock(),
		addrFilters: make([]*AddrFilter, 0),
	}
}

func (u *FilterTransport) AddAddrFilter(addrFilter *AddrFilter) error {

	u.addrFilters = append(u.addrFilters, addrFilter)
	return nil
}

func (u *FilterTransport) SendUnreliableMsgTo(ctx context.Context, b common.RawBytes,
	address net.Addr) error {

	select {
	case <-u.writeLock.Lock():
		defer u.writeLock.Unlock()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := setWriteDeadlineFromCtx(u.conn, ctx); err != nil {
		return err
	}
	n, err := u.conn.WriteTo(b, address)
	if n != len(b) {
		return common.NewBasicError("Wrote incomplete message", err, "wrote", n, "expected", len(b))
	}
	return err
}

func (u *FilterTransport) SendMsgTo(ctx context.Context, b common.RawBytes,
	address net.Addr) error {

	return u.SendUnreliableMsgTo(ctx, b, address)
}

func (u *FilterTransport) RecvFrom(ctx context.Context) (common.RawBytes, net.Addr, error) {

	n, addr, err := u.recvFrom(ctx)

	for ; err == nil; n, addr, err = u.recvFrom(ctx) {

		isAck, filterErr := u.filterOnAddr(addr)

		if filterErr != nil || isAck {
			return n, addr, filterErr
		}
	}

	return n, addr, err
}

func (u *FilterTransport) recvFrom(ctx context.Context) (common.RawBytes, *snet.Addr, error) {
	select {
	case <-u.readLock.Lock():
		defer u.readLock.Unlock()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	if err := setReadDeadlineFromCtx(u.conn, ctx); err != nil {
		return nil, nil, err
	}
	b := make(common.RawBytes, common.MaxMTU)
	n, address, err := u.conn.ReadFromSCION(b)

	return b[:n], address, err
}

func (u *FilterTransport) filterOnAddr(addr *snet.Addr) (bool, error) {

	for _, f := range u.addrFilters {
		result, err := (*f).FilterAddr(addr)
		switch result {
		case FilterError:
			return false, err
		case FilterAccept:
			continue
		case FilterDrop:
			return false, nil
		}
	}
	return true, nil
}

func (u *FilterTransport) Close(context.Context) error {
	return u.conn.Close()
}

func setWriteDeadlineFromCtx(conn net.PacketConn, ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetWriteDeadline(deadline)
	}
	return conn.SetWriteDeadline(time.Time{})
}

func setReadDeadlineFromCtx(conn net.PacketConn, ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetReadDeadline(deadline)
	}
	return conn.SetReadDeadline(time.Time{})
}
