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
	cmd                 = "./bin/filter_integration_base"
	configAndResultName = []string{"whitelist_ISD_no", "whitelist_allN_no", "whitelist_upDownN_no",
		"whitelist_coreN_no", "whitelist_no_AS"}

	AS120         = "1-ff00:0:120"
	srcASesFor120 = "1-ff00:0:110,1-ff00:0:111,1-ff00:0:112,1-ff00:0:120,1-ff00:0:121,1-ff00:0:130,1-ff00:0:132," +
		"2-ff00:0:210,2-ff00:0:220"
	AS111         = "1-ff00:0:111"
	srcASesFor111 = "1-ff00:0:110,1-ff00:0:111,1-ff00:0:112,1-ff00:0:120,1-ff00:0:121,1-ff00:0:130,1-ff00:0:132," +
		"2-ff00:0:211,2-ff00:0:220"
)

func main() {
	var errorCounter = 0
	for _, fileName := range configAndResultName {
		err := RunClient(fileName+"_AS120", srcASesFor120, AS120)
		if err != nil {
			errorCounter += 1
		}
	}

	for _, fileName := range configAndResultName {
		err := RunClient(fileName+"_AS111", srcASesFor111, AS111)
		if err != nil {
			errorCounter += 1
		}
	}

	if errorCounter > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func RunClient(configFileName, srcASes, dstASes string) error {
	command := exec.Command(cmd, "-filename", configFileName, "-srcIAs", srcASes, "-dstIAs", dstASes)

	command.Stdout = os.Stdout
	command.Stderr = os.Stdout

	return command.Run()
}