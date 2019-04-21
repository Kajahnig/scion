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

package per_as_rate_limiting

import (
	"context"
	"math"

	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/counting_bloom"
	"github.com/scionproto/scion/go/lib/periodic"
)

type rateLimitFilter struct {
	filter      *counting_bloom.CBF
	numCells    uint32
	numHashFunc uint32
	maxValue    uint32
}

func (f *rateLimitFilter) checkLimit(addr []byte) (filters.FilterResult, error) {
	rateLimitExceeded, err := f.filter.CheckIfRateLimitExceeded(addr)
	if err != nil {
		return filters.FilterError, err
	}
	if rateLimitExceeded {
		return filters.FilterDrop, nil
	}
	return filters.FilterAccept, nil
}

func filterFromConfig(cfg *RateLimitConfig) (*rateLimitFilter, error) {
	if cfg == nil {
		return nil, nil
	}

	numCells, numHashFunc := calculateOptimalParameters(float64(cfg.NumOfClients))
	maxValue := uint32(cfg.MaxCount)

	CBF, err := counting_bloom.NewCBF(numCells, numHashFunc, maxValue)
	if err != nil {
		return nil, err
	}

	filter := &rateLimitFilter{CBF, numCells, numHashFunc, maxValue}

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
