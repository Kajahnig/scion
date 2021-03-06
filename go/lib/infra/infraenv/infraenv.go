// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package infraenv contains convenience function common to SCION infra
// services.
package infraenv

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/svc"
)

const (
	ErrAppUnableToInitMessenger = "Unable to initialize SCION Infra Messenger"
)

// NetworkConfig describes the networking configuration of a SCION
// control-plane RPC endpoint.
type NetworkConfig struct {
	// IA is the local AS number.
	IA addr.IA
	// Public is the Internet-reachable address in the case where the service
	// is behind NAT.
	Public *snet.Addr
	// Bind is the local address the server should listen on.
	Bind *snet.Addr
	// SVC registers this server to receive packets with the specified SVC
	// destination address.
	SVC addr.HostSVC
	// TrustStore is the crypto backend for control-plane verification.
	TrustStore infra.TrustStore
	// ReconnectToDispatcher sets up sockets that automatically reconnect if
	// the dispatcher closes the connection (e.g., if the dispatcher goes
	// down).
	ReconnectToDispatcher bool
	// EnableQUICTest can be used to enable the QUIC RPC implementation.
	EnableQUICTest bool
	// Router is used by various infra modules for path-related operations. A
	// nil router means only intra-AS traffic is supported.
	Router snet.Router
}

// Messenger initializes a SCION control-plane RPC endpoint using the specified
// configuration.
func (nc *NetworkConfig) Messenger() (infra.Messenger, error) {
	conn, err := nc.initNetworking()
	if err != nil {
		return nil, err
	}

	router := nc.Router
	if router == nil {
		router = &snet.BaseRouter{IA: nc.IA}
	}

	msgerCfg := &messenger.Config{
		IA:         nc.IA,
		TrustStore: nc.TrustStore,
		AddressRewriter: &messenger.AddressRewriter{
			Router: router,
			Resolver: &svc.Resolver{
				LocalIA: nc.IA,
				ConnFactory: snet.NewDefaultPacketDispatcherService(
					reliable.NewDispatcherService(""),
				),
				Machine: buildLocalMachine(nc.Bind, nc.Public),
			},
			// XXX(scrye): Disable SVC resolution for the moment.
			SVCResolutionFraction: 0.00,
		},
	}
	if nc.EnableQUICTest {
		var err error
		msgerCfg.QUIC, err = buildQUICConfig(conn)
		if err != nil {
			return nil, err
		}
	} else {
		msgerCfg.Dispatcher = disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		)
	}
	msger := messenger.NewMessengerWithMetrics(msgerCfg)
	nc.TrustStore.SetMessenger(msger)
	return msger, nil

}

func buildLocalMachine(bind, public *snet.Addr) snet.LocalMachine {
	var mi snet.LocalMachine
	mi.PublicIP = public.Host.L3.IP()
	if bind != nil {
		mi.InterfaceIP = bind.Host.L3.IP()
	} else {
		mi.InterfaceIP = mi.PublicIP
	}
	return mi
}

func (nc *NetworkConfig) initNetworking() (net.PacketConn, error) {
	var network snet.Network
	network, err := snet.NewNetwork(nc.IA, "", reliable.NewDispatcherService(""))
	if err != nil {
		return nil, common.NewBasicError("Unable to create network", err)
	}
	if nc.ReconnectToDispatcher {
		network = snetproxy.NewProxyNetwork(network)
	}
	conn, err := network.ListenSCIONWithBindSVC("udp4", nc.Public, nc.Bind, nc.SVC, 0)
	if err != nil {
		return nil, common.NewBasicError("Unable to listen on SCION", err)
	}
	return conn, nil
}

// NewRouter constructs a path router for paths starting from localIA.
func NewRouter(localIA addr.IA, sd env.SciondClient) (snet.Router, error) {
	var err error
	var router snet.Router
	ticker := time.NewTicker(time.Second)
	timer := time.NewTimer(sd.InitialConnectPeriod.Duration)
	defer ticker.Stop()
	defer timer.Stop()
	// XXX(roosd): Initial retrying is implemented here temporarily.
	// In https://github.com/scionproto/scion/issues/1974 this will be
	// done transparently and pushed to snet.NewNetwork.
Top:
	for {
		sciondConn, err := sciond.NewService(sd.Path, true).Connect()
		router = &snet.BaseRouter{
			IA: localIA,
			PathResolver: pathmgr.New(
				sciondConn,
				pathmgr.Timers{
					NormalRefire: time.Minute,
					ErrorRefire:  3 * time.Second,
				},
				log.Root(),
			),
		}
		if err == nil {
			break
		}

		select {
		case <-ticker.C:
		case <-timer.C:
			break Top
		}
	}
	return router, err
}

func buildQUICConfig(conn net.PacketConn) (*messenger.QUICConfig, error) {
	// FIXME(scrye): Hardcode the crypto for now, because this is only used for
	// testing. To make QUIC RPC deployable, these need to be specified in the
	// configuration file.
	cert, err := tls.LoadX509KeyPair("gen-certs/tls.pem", "gen-certs/tls.key")
	if err != nil {
		return nil, err
	}

	return &messenger.QUICConfig{
		Conn: conn,
		TLSConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		},
	}, nil
}

func InitInfraEnvironment(topologyPath string) *env.Env {
	return InitInfraEnvironmentFunc(topologyPath, nil)
}

// InitInfraEnvironmentFunc sets up the environment by first calling
// env.RealoadTopology and then the provided function.
func InitInfraEnvironmentFunc(topologyPath string, f func()) *env.Env {
	return env.SetupEnv(
		func() {
			env.ReloadTopology(topologyPath)
			if f != nil {
				f()
			}
		},
	)
}
