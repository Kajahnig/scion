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
	"github.com/scionproto/scion/go/lib/periodic"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/filter_handler"
	"github.com/scionproto/scion/go/lib/infra/transport"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	ConfigDir     = "./go/integration/filter_configs"
	pathToLogFile = "logs/0_counters.log"
)

var (
	remote              snet.Addr
	requestFilterConfig string
	packetFilterConfig  string
	topoFilePath        string
	baseline            bool
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
		"(Mandatory for servers) Name of the request filter configuration in /filter_configs")
	flag.StringVar(&topoFilePath, "topoFilePath", "",
		"(Mandatory for servers) Path to the topology file of the server")
	flag.BoolVar(&baseline, "baseline", false, "If this a baseline test (needs counter handlers)")
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
	if integration.Mode == integration.ModeServer {
		if requestFilterConfig == "" {
			integration.LogFatal("Missing request filter config")
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

	//init the messenger
	msgr := messenger.New(
		&messenger.Config{
			IA: integration.Local.IA,
			Dispatcher: disp.New(
				transport.NewPacketTransport(conn),
				messenger.DefaultAdapter,
				log.Root(),
			),
			AddressRewriter: &messenger.AddressRewriter{
				Router: &snet.BaseRouter{IA: integration.Local.IA},
			},
		},
	)

	var cfg filter_handler.FilterHandlerConfig
	_, err = toml.DecodeFile(ConfigDir+"/"+requestFilterConfig+".toml", &cfg)
	if err != nil {
		integration.LogFatal("Unable to decode configuration file", "err", err)
	}
	cfg.InitDefaults()
	err = cfg.Validate()
	if err != nil {
		integration.LogFatal("Error validating the configuration file", "err", err)
	}

	log.Debug(fmt.Sprintf("%v", cfg))

	err = filter_handler.Init(integration.Local.IA, &cfg, topoFilePath)

	//add handlers to the messenger
	msgr.AddHandler(infra.TRCRequest, getOriginalHandler(infra.TRCRequest))
	msgr.AddHandler(infra.ChainRequest, getOriginalHandler(infra.ChainRequest))
	log.Debug("Listening", "local", conn.LocalAddr())

	f, err := os.OpenFile(pathToLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Crit("Error opening file to write counters", "err", err)
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("Stats from %v with config %v\n", time.Now(), requestFilterConfig))
	if err != nil {
		log.Crit("Error writing first sentence in stats file", "err", err)
	}

	//start periodic task that prints the counter every second
	if baseline {
		periodic.StartPeriodicTask(
			&counterPrinter{&counter},
			periodic.NewTicker(time.Second),
			time.Second)
	}
	//listen and serve with messenger
	msgr.ListenAndServe()
}

func getOriginalHandler(messageType infra.MessageType) infra.Handler {
	if baseline {
		return filter_handler.New(messageType, &countingHandler{})
	}
	return filter_handler.New(messageType,
		infra.HandlerFunc(func(r *infra.Request) *infra.HandlerResult {
			return infra.MetricsResultOk
		}))
}

var _ infra.Handler = (*countingHandler)(nil)

type countingHandler struct{}

func (h *countingHandler) Handle(r *infra.Request) *infra.HandlerResult {
	atomic.AddUint32(&counter, 1)
	return infra.MetricsResultOk
}

type counterPrinter struct {
	counter *uint32
}

func (c *counterPrinter) Run(ctx context.Context) {
	f, err := os.OpenFile(pathToLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Crit("Error opening file to write counters", "err", err)
	}
	defer f.Close()
	_, err = f.WriteString(strconv.Itoa(int(*c.counter)) + "\n")
	if err != nil {
		log.Crit("Error writing counter strings", "err", err)
	}
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
