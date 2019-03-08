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
	"log"
	"os"
	"os/exec"
)

var (
	cmd                 = "./bin/filter_integration_base"
	configAndResultName = []string{"pathlength_min0_max0", "pathlength_min0_max1", "pathlength_min0_max2",
		"pathlength_min1_max1", "pathlength_min1_max2", "pathlength_min2_max2"}
)

func main() {
	var errorCounter = 0
	for _, fileName := range configAndResultName {
		err := RunClient(fileName)
		if err != nil {
			errorCounter += 1
		}
	}

	if errorCounter > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func RunClient(configFileName string) error {
	command := exec.Command(cmd, "-filename", configFileName, "-srcASes", "1-ff00:0:110,1-ff00:0:111")

	command.Stdout = os.Stdout
	command.Stderr = os.Stdout

	if err := command.Run(); err != nil {
		log.Fatal(err)
	}

	return nil
}
