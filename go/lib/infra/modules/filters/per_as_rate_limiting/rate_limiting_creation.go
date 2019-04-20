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
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/counting_bloom"
	"github.com/scionproto/scion/go/lib/periodic"
)

const (
	//5 minutes default interval
	defaultInterval = 300 * time.Second

	//expected is 60 packets for non core, 120 for core ASes, plus 30% is 78 resp. 156 packets
	defaultMaxCount uint32 = 156
)

var _ filters.PacketFilter = (*PerASRateLimitFilter)(nil)

type PerASRateLimitFilter struct {
	localRateLimiting   bool
	outsideRateLimiting bool

	localFilterInfo   rateLimitFilterInfo
	outsideFilterInfo rateLimitFilterInfo

	localFilter   *counting_bloom.CBF
	outsideFilter *counting_bloom.CBF
}

type rateLimitFilterInfo struct {
	interval    time.Duration
	numCells    uint32
	numHashFunc uint32
	maxValue    uint32
}

func NewPerASRateLimitingFilterFromConfig(cfg *PerASRateLimitConfig) (*PerASRateLimitFilter, error) {
	var err error
	err = cfg.Validate()
	if err != nil {
		return nil, err
	}
	cfg.InitDefaults()

	local := false
	outside := false
	localFilterInfo := &rateLimitFilterInfo{}
	outsideFilterInfo := &rateLimitFilterInfo{}

	if cfg.LocalClients != 0 {
		local = true
		localFilterInfo, err = newRateLimitFilterInfo(cfg.LocalInterval.Duration,
			float64(cfg.LocalClients), uint32(cfg.LocalMaxCount))
		if err != nil {
			return nil, err
		}
	}
	if cfg.OutsideASes != 0 {
		outside = true
		outsideFilterInfo, err = newRateLimitFilterInfo(cfg.OutsideInterval.Duration,
			float64(cfg.OutsideASes), uint32(cfg.OutsideMaxCount))
		if err != nil {
			return nil, err
		}
	}
	return newPerASRateLimitFilter(local, outside, localFilterInfo, outsideFilterInfo)
}

func newRateLimitFilterInfo(interval time.Duration, numElementsToCount float64, maxValue uint32) (*rateLimitFilterInfo, error) {

	numCells, numHashFunc := calculateOptimalParameters(numElementsToCount)
	return &rateLimitFilterInfo{
		interval, numCells,
		numHashFunc, maxValue}, nil
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

func newPerASRateLimitFilter(localRateLimiting, outsideRateLimiting bool,
	localFilterInfo, outsideFilterInfo *rateLimitFilterInfo) (*PerASRateLimitFilter, error) {

	if !localRateLimiting && !outsideRateLimiting {
		return nil, common.NewBasicError("rate limiting filter cannot be initialized"+
			" with no local and no outside rate limiting", nil)
	}

	var err error
	var localFilter *counting_bloom.CBF
	var outsideFilter *counting_bloom.CBF

	if localRateLimiting {
		localFilter, err = createCBFFromRateLimitFilterInfo(localFilterInfo)
		if err != nil {
			return nil, err
		}
	}
	if outsideRateLimiting {
		outsideFilter, err = createCBFFromRateLimitFilterInfo(outsideFilterInfo)
		if err != nil {
			return nil, err
		}
	}

	filter := &PerASRateLimitFilter{
		localRateLimiting, outsideRateLimiting,
		*localFilterInfo, *outsideFilterInfo,
		localFilter, outsideFilter,
	}

	if filter.localRateLimiting {
		periodic.StartPeriodicTask(
			&FilterResetter{filter.localFilter},
			periodic.NewTicker(localFilterInfo.interval),
			localFilterInfo.interval)
	}
	if filter.outsideRateLimiting {
		periodic.StartPeriodicTask(
			&FilterResetter{filter.outsideFilter},
			periodic.NewTicker(outsideFilterInfo.interval),
			outsideFilterInfo.interval)
	}

	return filter, nil
}

func createCBFFromRateLimitFilterInfo(info *rateLimitFilterInfo) (*counting_bloom.CBF, error) {
	cbf, err := counting_bloom.NewCBF(info.numCells, info.numHashFunc, info.maxValue)
	if err != nil {
		return nil, err
	}
	return cbf, nil
}

type FilterResetter struct {
	filter *counting_bloom.CBF
}

func (f *FilterResetter) Run(ctx context.Context) {
	f.filter.Reset()
}
