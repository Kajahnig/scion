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
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	name         = "test_runner_"
	cmd          = "./bin/test_server_and_client"
	dstASList    = "1-ff00:0:120"
	topoFilePath = "./filter_topos/"

	runWithInfra        bool
	baseline            string
	sleepTime           int
	requestFilterConfig string
	packetFilterConfig  string
	topoFileName        string
)

func addFlags() {
	flag.BoolVar(&runWithInfra, "infra", false, "whether the server should run with the infra (default false)")
	flag.IntVar(&sleepTime, "time", 20, "How long the server should run (seconds)")
	flag.StringVar(&requestFilterConfig, "rfConfig", "",
		"(Mandatory for servers) Name of the request filter configuration in ./go/integration/filter_configs")
	flag.StringVar(&packetFilterConfig, "pfConfig", "",
		"(Mandatory for servers) Name of the packet filter configuration in ./go/integration/filter_configs")
	flag.StringVar(&topoFileName, "topo", "default_topology",
		"(Mandatory for servers) Name of the topology file in ./filter_topos")
}

func main() {
	addFlags()
	flag.Parse()
	os.Exit(realMain())
}

func realMain() int {
	intTestName := name + requestFilterConfig + "_" + packetFilterConfig
	log.Info("Starting integration test for " + intTestName)
	if err := integration.InitWithGivenIAs(intTestName, "", dstASList); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	defer log.Flush()
	var serverArgs []string
	if runWithInfra {
		serverArgs = []string{
			"-local", integration.DstAddrPattern + ":12345",
			"-mode", "server",
			"-log.console", "debug",
			"-pfConfig", packetFilterConfig,
			"-rfConfig", requestFilterConfig,
			"-topoFilePath", topoFilePath + topoFileName + ".json",
		}
	} else {
		serverArgs = []string{
			"-local", integration.DstAddrPattern + ":12345",
			"-mode", "server",
			"-sciond", "/run/shm/sciond/1-ff00_0_120.sock",
			"-log.console", "debug",
			"-pfConfig", packetFilterConfig,
			"-rfConfig", requestFilterConfig,
			"-topoFilePath", topoFilePath + topoFileName + ".json",
		}
	}
	in := integration.NewBinaryIntegration(intTestName, cmd, []string{}, serverArgs)
	if err := runTests(in, integration.IAPairs(integration.DispAddr)); err != nil {
		log.Error("Error during tests: " + err.Error())
		return 1
	}
	return 0
}

// RunTests runs the client and server for each IAPair.
// In case of an error the function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name()+"_server", func() error {
		// First run all servers
		dsts := integration.ExtractUniqueDsts(pairs)
		for _, dst := range dsts {
			s, err := integration.StartServer(in, dst)
			if err != nil {
				log.Error(fmt.Sprintf("Error in server: %s", dst.String()), "err", err)
				return common.NewBasicError(fmt.Sprintf("Server %s exited with an error", dst.String()), nil)
			}
			defer s.Close()
		}
		time.Sleep(time.Duration(sleepTime) * time.Second)
		log.Info(fmt.Sprintf("Slept for %v seconds", sleepTime))
		return nil
	})
}
