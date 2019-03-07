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
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	name                = "pathlength_filter_integration"
	cmd                 = "./bin/filter_common"
	attempts            = flag.Int("attempts", 1, "Number of attempts before giving up.")
	configAndResultName = []string{"pathlength_min0_max0"} //, "pathlength_min0_max1"}
)

func main() {
	var errorCounter = 0
	for _, testFileName := range configAndResultName {
		errorCounter += realMain(testFileName)
	}
	if errorCounter > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func realMain(testFileName string) int {
	if err := integration.Init(name); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	defer log.Flush()
	clientArgs := []string{"-log.console", "debug", "-attempts", strconv.Itoa(*attempts),
		"-local", integration.SrcAddrPattern + ":0",
		"-remote", integration.DstAddrPattern + ":" + integration.ServerPortReplace,
		"-results", testFileName}
	serverArgs := []string{"-log.console", "debug", "-mode", "server",
		"-local", integration.DstAddrPattern + ":0",
		"-config", testFileName}
	in := integration.NewBinaryIntegration(name, cmd, clientArgs, serverArgs)
	if err := runTests(in, integration.IAPairs(integration.DispAddr)); err != nil {
		log.Error("Error during tests: " + err.Error())
		return 1
	}
	return 0
}

// RunTests runs the client and server for each IAPair.
// In case of an error the function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name(), func() error {
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
		// Now start the clients for srcDest pair
		errorCount := 0
		for i, conn := range pairs {
			testInfo := fmt.Sprintf("%v -> %v (%v/%v)", conn.Src.IA, conn.Dst.IA, i+1, len(pairs))
			log.Info(fmt.Sprintf("Test %v: %s", in.Name(), testInfo))
			t := integration.DefaultRunTimeout + integration.CtxTimeout*time.Duration(*attempts)
			if err := integration.RunClient(in, conn, t); err != nil {
				log.Error(fmt.Sprintf("Error in client: %s", testInfo), "err", err)
				errorCount++
			}
		}
		if errorCount != 0 {
			return common.NewBasicError(fmt.Sprintf("%v clients exited with an error", errorCount), nil)
		}
		return nil
	})
}
