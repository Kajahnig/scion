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

package path_length

import (
	"io"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
)

const pathLengthSample = `
# allow empty/no paths
AllowEmptyPaths = true

# disallow any path that is non empty
DisallowPaths = false

# set min path length
MinPathLength = 1

#set max path length
MaxPathLength = 2
`

var _ config.Config = (*PathLengthConfig)(nil)

type PathLengthConfig struct {
	AllowEmptyPaths bool
	DisallowPaths   bool
	MinPathLength   int
	MaxPathLength   int
}

func (cfg *PathLengthConfig) InitDefaults() {
	if !cfg.DisallowPaths && cfg.MinPathLength == 0 {
		cfg.MinPathLength = 1
	}
}

func (cfg PathLengthConfig) Validate() error {
	if !cfg.AllowEmptyPaths && cfg.DisallowPaths {
		return common.NewBasicError("Not allowing empty paths and disallowing other paths blocks all traffic",
			nil)
	}
	if cfg.DisallowPaths && (cfg.MinPathLength != 0 || cfg.MaxPathLength != 0) {
		return common.NewBasicError("Min and max path settings will not take effect as paths are disallowed",
			nil)
	}

	if cfg.MaxPathLength != 0 && cfg.MaxPathLength < cfg.MinPathLength {
		return common.NewBasicError("Max Path length is smaller than min path length", nil)
	}
	if cfg.MaxPathLength < 0 {
		return common.NewBasicError("Max Path is negative", nil)
	}
	if cfg.MinPathLength < 0 {
		return common.NewBasicError("Min Path is negative", nil)
	}
	if cfg.MinPathLength == 0 && !cfg.DisallowPaths {
		return common.NewBasicError("Min path length cannot be 0", nil)
	}
	return nil
}

func (cfg PathLengthConfig) ConfigName() string {
	return "pathlength"
}

func (cfg PathLengthConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, pathLengthSample)
}
