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
//
//
// An Interval Request Limit Filter filters according to the number of requests per AS (FilterExternal)
// or per IP (FilterInternal) that have been seen in a certain time interval.
// The underlying data structure to approximate the number of sent requests is a Counting Bloom Filter, dimensioned
// for a false positivity rate of 10% and increasing the counter with the minimum increase algorithm (only increases the
// counter with the minimum value).
//
// The filter can be configured with the following parameters:
// - number of clients: the number of distinctive ASes or IPS for which requests should be counted
// - max Value: 		the number of allowed requests, that - when it is reached - results in drop of further requests
// - interval: 			the time after which the counting bloom filter is reset
//

package interval_request_limiting

import (
	"context"
	"math"

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/counting_bloom"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
)

const ErrMsg = "Request limit exceeded"

var _ request_filters.InternalFilter = (*IntervalRequestLimitFilter)(nil)
var _ request_filters.ExternalFilter = (*IntervalRequestLimitFilter)(nil)

type IntervalRequestLimitFilter struct {
	filter      *counting_bloom.CBF
	numCells    uint32
	numHashFunc uint32
	maxValue    uint32
}

func (f *IntervalRequestLimitFilter) FilterInternal(addr snet.Addr) (filters.FilterResult, error) {
	addrAsBytes := []byte(addr.Host.L3.IP().String())
	return f.checkLimit(addrAsBytes)
}

func (f *IntervalRequestLimitFilter) FilterExternal(addr snet.Addr) (filters.FilterResult, error) {
	addrAsBytes := []byte(addr.IA.String())
	return f.checkLimit(addrAsBytes)
}

func (f *IntervalRequestLimitFilter) ErrorMessage() string {
	return ErrMsg
}

func (f *IntervalRequestLimitFilter) checkLimit(addr []byte) (filters.FilterResult, error) {
	rateLimitExceeded, err := f.filter.CheckIfRateLimitExceeded(addr)
	if err != nil {
		return filters.FilterError, err
	}
	if rateLimitExceeded {
		return filters.FilterDrop, nil
	}
	return filters.FilterAccept, nil
}

func FilterFromConfig(cfg *RateLimitConfig) (*IntervalRequestLimitFilter, error) {
	if cfg == nil {
		return nil, nil
	}

	numCells, numHashFunc := calculateOptimalParameters(float64(cfg.NumOfClients))
	maxValue := uint32(cfg.MaxCount)

	CBF, err := counting_bloom.NewCBF(numCells, numHashFunc, maxValue)
	if err != nil {
		return nil, err
	}

	filter := &IntervalRequestLimitFilter{CBF, numCells, numHashFunc, maxValue}

	periodic.StartPeriodicTask(
		&FilterResetter{filter.filter},
		periodic.NewTicker(cfg.Interval.Duration),
		cfg.Interval.Duration)

	return filter, nil
}

func calculateOptimalParameters(numOfElementsToCount float64) (uint32, uint32) {
	numberOfCells := math.Ceil(-1 * numOfElementsToCount * math.Log(0.1) / math.Pow(math.Ln2, 2))
	numberOfHashFunctions1 := math.Floor((numberOfCells * math.Ln2) / numOfElementsToCount)
	numberOfHashFunctions2 := numberOfHashFunctions1 + 1

	p := math.Pow(1-1/numberOfCells, numOfElementsToCount)
	fpr1 := math.Pow(1-math.Pow(p, numberOfHashFunctions1), numberOfHashFunctions1)
	fpr2 := math.Pow(1-math.Pow(p, numberOfHashFunctions2), numberOfHashFunctions2)

	if fpr1 < fpr2 {
		return uint32(math.Max(numberOfCells, 1)), uint32(numberOfHashFunctions1)
	}
	return uint32(math.Max(numberOfCells, 1)), uint32(numberOfHashFunctions2)
}

type FilterResetter struct {
	filter *counting_bloom.CBF
}

func (f *FilterResetter) Run(ctx context.Context) {
	f.filter.Reset()
}
