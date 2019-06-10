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

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/filter_handler"
	"github.com/scionproto/scion/go/lib/infra/transport"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	ConfigDir     = "./go/integration/filter_configs"
	pathToLogFile = "logs/0_counters.log"
)

var (
	remote              snet.Addr
	requestFilterConfig string
	topoFilePath        string
	counter             uint32
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.LogPanicAndExit()
	defer log.Flush()
	addFlags()
	integration.SetupWithPacketFilters()
	validateFlags()
	if integration.Mode == integration.ModeServer {
		server{}.run()
		return 0
	} else {
		return client{}.run()
	}
}

func addFlags() {
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
	flag.StringVar(&requestFilterConfig, "rfConfig", "",
		"(Mandatory for servers) Name of the request filter config in "+ConfigDir)
	flag.StringVar(&topoFilePath, "topoFilePath", "",
		"(Mandatory for servers) Path to the topology file of the server")
}

func validateFlags() {
	if integration.Mode == integration.ModeClient {
		if remote.Host == nil {
			integration.LogFatal("Missing remote address")
		}
		if remote.Host.L4 == nil {
			integration.LogFatal("Missing remote port")
		}
		if remote.Host.L4.Port() == 0 {
			integration.LogFatal("Invalid remote port", "remote port", remote.Host.L4.Port())
		}
	}
}

type server struct {
	conn snet.Conn
}

func (s server) run() {
	conn, err := snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", conn.LocalAddr().(*snet.Addr).Host.L4.Port())
		fmt.Printf("%s%s\n", libint.ReadySignal, integration.Local.IA)
	}

	cfg := filter_handler.FilterHandlerConfig{}
	if requestFilterConfig != "" {
		_, err = toml.DecodeFile(ConfigDir+"/"+requestFilterConfig+".toml", &cfg)
		if err != nil {
			integration.LogFatal("Unable to decode configuration file", "err", err)
		}
	}

	err = filter_handler.Init(integration.Local.IA, &cfg, topoFilePath)
	if err != nil {
		integration.LogFatal("Error initializing the filter handler", "err", err)
	}

	handler := filter_handler.NewAddrFilterHandler(infra.TRCRequest)
	log.Debug("Listening", "local", conn.LocalAddr())

	f, err := os.OpenFile(pathToLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Crit("Error opening file to write counters", "err", err)
	}
	_, err = f.WriteString(fmt.Sprintf("Stats from counting connection packets at %v using config '%v' and"+
		" topology '%v'\n", time.Now(), requestFilterConfig, topoFilePath))
	if err != nil {
		log.Crit("Error writing first sentence in stats file", "err", err)
	}

	f.Close()

	periodic.StartPeriodicTask(
		&counterPrinter{counter: &filter_handler.Counter},
		periodic.NewTicker(time.Second),
		time.Second)

	for i := 0; i < 10; i++ {

		go func() {
			b := make(common.RawBytes, 1024)

			for {
				_, addr, err := conn.ReadFromSCION(b)
				if err != nil {
					log.Error("Error reading packet", "err", err)
					continue
				}
				go func() {
					handler.HandleAddr(addr)
				}()
			}
		}()
	}

	b := make(common.RawBytes, 1024)

	for {
		_, addr, err := conn.ReadFromSCION(b)
		if err != nil {
			log.Error("Error reading packet", "err", err)
			continue
		}
		go func() {
			handler.HandleAddr(addr)
		}()
	}
}

var _ infra.Handler = (*countingHandler)(nil)

type countingHandler struct{}

func (h *countingHandler) Handle(r *infra.Request) *infra.HandlerResult {
	atomic.AddUint32(&counter, 1)

	return infra.MetricsResultOk
}

type counterPrinter struct {
	counter         *uint32
	instanceCounter int
	previousCounter int
}

func (c *counterPrinter) Run(ctx context.Context) {
	f, err := os.OpenFile(pathToLogFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Crit("Error opening file to write counters", "err", err)
	}
	defer f.Close()
	actualCounter := int(*c.counter)
	_, err = f.WriteString(strconv.Itoa(c.instanceCounter) + ": " + strconv.Itoa(actualCounter-c.previousCounter) + "\n")
	if err != nil {
		log.Crit("Error writing counter strings", "err", err)
	}
	c.instanceCounter += 1
	c.previousCounter = actualCounter
}

type client struct {
	conn snet.Conn
	msgr infra.Messenger
}

func (c client) run() int {
	var err error

	c.conn, err = snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())

	c.msgr = messenger.New(
		&messenger.Config{
			IA: integration.Local.IA,
			Dispatcher: disp.New(
				transport.NewPacketTransport(c.conn),
				messenger.DefaultAdapter,
				log.Root(),
			),
			AddressRewriter: &messenger.AddressRewriter{
				Router: &snet.BaseRouter{IA: integration.Local.IA},
			},
		},
	)

	return c.requestAll()
}

func (c client) requestAll() int {
	err := c.requestTRC()
	if err != nil {
		log.Error("Error sending TRC request", "err", err)
	}
	err = c.requestCert()
	if err != nil {
		log.Error("Error sending Chain request", "err", err)
	}
	err = c.requestSegment()
	if err != nil {
		log.Error("Error sending Segment request", "err", err)
	}
	return 0
}

func (c client) requestTRC() error {
	req := &cert_mgmt.TRCReq{
		CacheOnly: false,
		ISD:       remote.IA.I,
		Version:   scrypto.LatestVer,
	}
	//log.Info("Request to Server: TRC request", "remote", remote.IA)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()

	_, err := c.msgr.GetTRC(ctx, req, &remote, messenger.NextId())
	return err
}

func (c client) requestCert() error {
	req := &cert_mgmt.ChainReq{
		CacheOnly: false,
		RawIA:     remote.IA.IAInt(),
		Version:   scrypto.LatestVer,
	}
	//log.Info("Request to Server: Chain request", "remote", remote.IA)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()

	_, err := c.msgr.GetCertChain(ctx, req, &remote, messenger.NextId())
	return err
}

func (c client) requestSegment() error {
	req := &path_mgmt.SegReq{
		RawSrcIA: remote.IA.IAInt(),
		RawDstIA: integration.Local.IA.IAInt(),
	}

	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()

	_, err := c.msgr.GetSegs(ctx, req, &remote, messenger.NextId())
	return err
}
