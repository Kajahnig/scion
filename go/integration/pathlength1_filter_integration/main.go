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
	cmd        = "./bin/second_filter_integration_base"
	pathLength = "pathlength1"
	core       = "seglength_core"
	noncore    = "seglength_noncore"

	AS122         = "1-ff00:0:122"
	srcASesFor122 = "1-ff00:0:110,1-ff00:0:111,1-ff00:0:112,1-ff00:0:121,1-ff00:0:131,1-ff00:0:133," +
		"2-ff00:0:210,2-ff00:0:220"
	topoPath122 = "./gen/ISD1/ASff00_0_122/endhost/topology.json"

	AS132         = "1-ff00:0:132"
	srcASesFor132 = "1-ff00:0:120,1-ff00:0:121,1-ff00:0:122,1-ff00:0:131,1-ff00:0:133," +
		"2-ff00:0:210,2-ff00:0:220"
	topoPath132 = "./gen/ISD1/ASff00_0_132/endhost/topology.json"

	AS120             = "1-ff00:0:120"
	AS111             = "1-ff00:0:111"
	srcASesForSegTest = "1-ff00:0:110,1-ff00:0:130,1-ff00:0:133," +
		"2-ff00:0:210,2-ff00:0:211,2-ff00:0:220,2-ff00:0:221"
	topoPath120 = "./gen/ISD1/ASff00_0_120/endhost/topology.json"
	topoPath111 = "./gen/ISD1/ASff00_0_111/endhost/topology.json"
)

func main() {
	var errorCounter = 0
	err := RunClient("pathlength1", srcASesFor122, AS122, topoPath122)
	if err != nil {
		errorCounter += 1
	}

	err = RunClient("pathlength1", srcASesFor132, AS132, topoPath132)
	if err != nil {
		errorCounter += 1
	}

	err = RunClient(core, srcASesForSegTest, AS120, topoPath120)
	if err != nil {
		errorCounter += 1
	}

	err = RunClient(noncore, srcASesForSegTest, AS111, topoPath111)
	if err != nil {
		errorCounter += 1
	}

	if errorCounter > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func RunClient(configFileName, srcASes, dstASes, topoFilePath string) error {
	command := exec.Command(cmd, "-filename", configFileName,
		"-srcIAs", srcASes, "-dstIAs", dstASes, "-topoFilePath", topoFilePath)

	command.Stdout = os.Stdout
	command.Stderr = os.Stdout

	return command.Run()
}
