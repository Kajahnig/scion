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

package filter_creation

import (
	"fmt"
	"io"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/packet_filters/drkey_filter"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/path_length"
)

var _ config.Config = (*PacketFilterConfig)(nil)

type PacketFilterConfig struct {
	Pathlength *path_length.PathLengthConfig
	Drkey      *drkey_filter.DRKeyConfig
}

func (cfg *PacketFilterConfig) InitDefaults() {
	if cfg.Pathlength != nil {
		cfg.Pathlength.InitDefaults()
	}
	if cfg.Drkey != nil {
		cfg.Drkey.InitDefaults()
	}
}

func (cfg *PacketFilterConfig) Validate() error {
	if cfg.Pathlength != nil {
		err := cfg.Pathlength.Validate()
		if err != nil {
			return common.NewBasicError("Unable to validate", err,
				"type", fmt.Sprintf("%T", cfg.Pathlength))
		}
	}
	if cfg.Drkey != nil {
		err := cfg.Drkey.Validate()
		if err != nil {
			return common.NewBasicError("Unable to validate", err,
				"type", fmt.Sprintf("%T", cfg.Drkey))
		}
	}
	return nil
}

func (cfg *PacketFilterConfig) ConfigName() string {
	return "filters"
}

func (cfg *PacketFilterConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteSample(dst, path, ctx,
		&(path_length.PathLengthConfig{}),
		&(drkey_filter.DRKeyConfig{}))
}
