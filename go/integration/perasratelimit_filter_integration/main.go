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
	cmd     = "./bin/filter_integration_base"
	servers = "1-ff00:0:111,1-ff00:0:120"

	//case1: only local rate limiting, 16bit case, 'lots of requests'
	case1FileName   = "perasratelimit_only_local"
	srcASesForCase1 = "1-ff00:0:111,1-ff00:0:120"

	//case2: only outside rate limiting, 8bit case, 'lots of ASes'
	case2FileName   = "perasratelimit_only_outside"
	srcASesForCase2 = "1-ff00:0:110,1-ff00:0:111,1-ff00:0:112,1-ff00:0:120,1-ff00:0:121,1-ff00:0:122," +
		"1-ff00:0:130,1-ff00:0:131,1-ff00:0:132,1-ff00:0:133," +
		"2-ff00:0:210,2-ff00:0:211,2-ff00:0:212,2-ff00:0:220,2-ff00:0:221,2-ff00:0:222"

	//case3: local and outside rate limiting, 8bit, 'mixed rate limiting case'
	case3FileName   = "perasratelimit_local_and_outside"
	srcASesForCase3 = "1-ff00:0:110,1-ff00:0:111,1-ff00:0:112,1-ff00:0:120,1-ff00:0:122,1-ff00:0:132," +
		"2-ff00:0:220,2-ff00:0:211,2-ff00:0:221"
)

func main() {
	var errorCounter = 0

	err := RunClient(case1FileName, srcASesForCase1, servers, "4")
	if err != nil {
		errorCounter += 1
	}
	err = RunClient(case2FileName, srcASesForCase2, servers, "32")
	if err != nil {
		errorCounter += 1
	}
	err = RunClient(case3FileName, srcASesForCase3, servers, "18")
	if err != nil {
		errorCounter += 1
	}

	if errorCounter > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func RunClient(configFileName, srcASes, dstASes, goRoutines string) error {
	command := exec.Command(cmd, "-filename", configFileName, "-srcIAs", srcASes, "-dstIAs", dstASes,
		"-goRoutines", goRoutines)

	command.Stdout = os.Stdout
	command.Stderr = os.Stdout

	return command.Run()
}
