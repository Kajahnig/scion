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
	"strconv"

	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	name                  = "test_runner"
	cmd                   = "./bin/test_server_and_client"
	runAlone              = flag.Bool("alone", false, "If the server should be run with a separate sciond and dispatcher")
	attempts              = 1              //flag.Int("attempts", 1, "Number of attempts before giving up.")
	maxNumberOfGoRoutines = 16             //flag.Int("goRoutines", 2, "Maximum number of goroutines.")
	srcASList             = ""             //flag.String("srcIAs", "", "Comma separated list of source IAs (clients).")
	dstASList             = "1-ff00:0:120" //flag.String("dstIAs", "", "Comma separated list of destination IAs (servers).")
)

func main() {
	flag.Parse()
	os.Exit(realMain())
}

func realMain() int {
	intTestName := name
	log.Info("Starting integration test for " + intTestName)
	if *runAlone {
		srcASList = "1-ff00:0:120"
	}
	if err := integration.InitWithGivenIAs(intTestName, srcASList, dstASList); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	defer log.Flush()
	var clientArgs []string
	if *runAlone {
		clientArgs = []string{"-log.console", "debug", "-attempts", strconv.Itoa(attempts),
			"-local", integration.SrcAddrPattern + ":0",
			"-remote", integration.DstAddrPattern + ":12345",
			"-sciond", "/run/shm/sciond/1-ff00_0_120.sock"}
	} else {
		clientArgs = []string{"-log.console", "debug", "-attempts", strconv.Itoa(attempts),
			"-local", integration.SrcAddrPattern + ":0",
			"-remote", integration.DstAddrPattern + ":12345"}
	}
	in := integration.NewBinaryIntegration(intTestName, cmd, clientArgs, []string{})
	if err := runTests(in, integration.IAPairs(integration.DispAddr)); err != nil {
		log.Error("Error during tests: " + err.Error())
		return 1
	}
	return 0
}

// RunTests runs the client and server for each IAPair.
// In case of an error the function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name()+"_clients", func() error {
		// Now start the clients for srcDest pair in parallel
		timeout := integration.DefaultRunTimeout + 5*integration.CtxTimeout
		return integration.RunUnaryTestsWithMoreGoRoutines(in, pairs, timeout, maxNumberOfGoRoutines)
	})
}
