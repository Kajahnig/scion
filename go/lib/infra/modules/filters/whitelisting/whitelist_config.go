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

package whitelisting

import (
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
)

const whitelistConfigSample = `
#path to topology file
PathToTopoFile = "../whitelisting/topology.json"

#how often the topology file should be rescanned
RescanInterval = "40m"

#How requests from outside of the local AS should be filtered
OutsideWLSetting = "ISD"

#How requests from the local AS should be filtered
LocalWLSetting = "infra"
`

var _ config.Config = (*WhitelistConfig)(nil)

type WhitelistConfig struct {
	PathToTopoFile   string
	RescanInterval   duration
	OutsideWLSetting outsideSetting
	LocalWLSetting   localSetting
}

func (cfg *WhitelistConfig) InitDefaults() {
	if cfg.RescanInterval.Duration == 0 {
		cfg.RescanInterval = duration{24 * time.Hour}
	}
}

func (cfg *WhitelistConfig) Validate() error {
	_, err := getTopo(cfg.PathToTopoFile)
	if err != nil {
		return common.NewBasicError("Invalid topology file",
			nil, "err", err)
	}
	if cfg.RescanInterval.Duration <= 0 {
		return common.NewBasicError("Negative or zero rescanning interval",
			nil, "interval", cfg.RescanInterval.Duration)
	}
	if cfg.LocalWLSetting.LocalWLSetting == NoLocalWL && cfg.OutsideWLSetting.OutsideWLSetting == NoOutsideWL {
		return common.NewBasicError("Cannot initialise whitelisting filter with no local"+
			" and no outside whitelisting", nil)
	}
	return nil
}

func (cfg *WhitelistConfig) ConfigName() string {
	return "whitelist"
}

func (cfg *WhitelistConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, whitelistConfigSample)
}

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

type outsideSetting struct {
	OutsideWLSetting
}

func (s *outsideSetting) UnmarshalText(text []byte) error {
	stringFormat := string(text)
	switch stringFormat {
	case ISD_value:
		s.OutsideWLSetting = WLISD
	case allNeighbours_value:
		s.OutsideWLSetting = WLAllNeighbours
	case upAndDownNeighbours_value:
		s.OutsideWLSetting = WLUpAndDownNeighbours
	case coreNeighbours_value:
		s.OutsideWLSetting = WLCoreNeighbours
	case no_value:
		s.OutsideWLSetting = NoOutsideWL
	default:
		return common.NewBasicError("Unknown value for outside whitelist setting",
			nil, "value", stringFormat)
	}
	return nil
}

type localSetting struct {
	LocalWLSetting
}

func (s *localSetting) UnmarshalText(text []byte) error {
	stringFormat := string(text)
	switch stringFormat {
	case AS_value:
		s.LocalWLSetting = WLLocalAS
	case infra_value:
		s.LocalWLSetting = WLLocalInfraNodes
	case no_value:
		s.LocalWLSetting = NoLocalWL
	default:
		return common.NewBasicError("Unknown value for local whitelist setting",
			nil, "value", stringFormat)
	}
	return nil
}
