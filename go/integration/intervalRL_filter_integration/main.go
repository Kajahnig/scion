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
	"os"
	"os/exec"
)

var (
	cmd         = "./bin/second_filter_integration_base"
	servers     = "1-ff00:0:111,1-ff00:0:120"
	AS120       = "1-ff00:0:120"
	topoPath120 = "./gen/ISD1/ASff00_0_120/br1-ff00_0_120-1/topology.json"
	AS111       = "1-ff00:0:111"
	topoPath111 = "./gen/ISD1/ASff00_0_111/br1-ff00_0_111-1/topology.json"

	//case1: only local rate limiting, 16bit case, 'lots of requests'
	case1FileName   = "intervalRL_internal"
	srcASesForCase1 = "1-ff00:0:111,1-ff00:0:120"

	//case2: only outside rate limiting, 8bit case, 'lots of ASes'
	case2FileName   = "intervalRL_external"
	srcASesForCase2 = "1-ff00:0:110,1-ff00:0:111,1-ff00:0:112,1-ff00:0:120,1-ff00:0:121,1-ff00:0:122," +
		"1-ff00:0:130,1-ff00:0:131,1-ff00:0:132,1-ff00:0:133," +
		"2-ff00:0:210,2-ff00:0:211,2-ff00:0:212,2-ff00:0:220,2-ff00:0:221"

	//case3: local and outside rate limiting, 8bit, 'mixed rate limiting case'
	case3FileName       = "intervalRL_internal_and_external"
	srcASesForCase3_111 = "1-ff00:0:111,1-ff00:0:112,1-ff00:0:120,1-ff00:0:121,1-ff00:0:130,2-ff00:0:211"
	srcASesForCase3_120 = "1-ff00:0:110,1-ff00:0:111,1-ff00:0:120,1-ff00:0:121,1-ff00:0:130,2-ff00:0:220"
)

func main() {
	var errorCounter = 0
	var err error

	err = RunClient(case1FileName, srcASesForCase1, AS111, "2", topoPath111)
	if err != nil {
		errorCounter += 1
	}
	err = RunClient(case1FileName, srcASesForCase1, AS120, "2", topoPath120)
	if err != nil {
		errorCounter += 1
	}

	err = RunClient(case2FileName, srcASesForCase2, AS111, "16", topoPath111)
	if err != nil {
		errorCounter += 1
	}
	err = RunClient(case2FileName, srcASesForCase2, AS120, "16", topoPath120)
	if err != nil {
		errorCounter += 1
	}

	err = RunClient(case3FileName, srcASesForCase3_111, AS111, "6", topoPath111)
	if err != nil {
		errorCounter += 1
	}
	err = RunClient(case3FileName, srcASesForCase3_120, AS120, "6", topoPath120)
	if err != nil {
		errorCounter += 1
	}

	if errorCounter > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func RunClient(configFileName, srcASes, dstASes, goRoutines, topoFilePath string) error {
	command := exec.Command(cmd, "-filename", configFileName, "-srcIAs", srcASes, "-dstIAs", dstASes,
		"-goRoutines", goRoutines, "-topoFilePath", topoFilePath)

	command.Stdout = os.Stdout
	command.Stderr = os.Stdout

	return command.Run()
}
