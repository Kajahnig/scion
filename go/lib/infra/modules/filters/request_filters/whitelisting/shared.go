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
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/snet"
)

const ErrMsg = "Not on whitelist"

var _ filters.InternalFilter = (*DroppingFilter)(nil)
var _ filters.ExternalFilter = (*DroppingFilter)(nil)

type DroppingFilter struct{}

func (f *DroppingFilter) FilterInternal(addr snet.Addr) (filters.FilterResult, error) {
	return filters.FilterDrop, nil
}

func (f *DroppingFilter) FilterExternal(addr snet.Addr) (filters.FilterResult, error) {
	return filters.FilterDrop, nil
}

func (f *DroppingFilter) ErrorMessage() string {
	return ErrMsg
}
