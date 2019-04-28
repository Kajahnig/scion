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

package drkey_filter

import (
	"io"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
)

const drkeySample = `
#If AS internal packets need to be authenticated with DRKey
InternalFiltering = true
#If external packets need to be authenticated with DRKey
ExternalFiltering = false
`

var _ config.Config = (*DRKeyConfig)(nil)

type DRKeyConfig struct {
	config.NoDefaulter
	InternalFiltering bool
	ExternalFiltering bool
}

func (cfg DRKeyConfig) Validate() error {
	if !cfg.InternalFiltering && !cfg.ExternalFiltering {
		return common.NewBasicError("DRKey filter with internal and external filtering disabled "+
			"only adds overhead", nil)
	}
	return nil
}

func (cfg DRKeyConfig) ConfigName() string {
	return "DRKey"
}

func (cfg DRKeyConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, drkeySample)
}
