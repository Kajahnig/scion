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

package filter_handler

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/filters"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/per_as_rate_limiting"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/whitelisting/whitelist_filters"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

var (
	localIA        addr.IA
	cfg            *FilterHandlerConfig
	pathToTopoFile string

	//WL filters
	infraFilter     *whitelist_filters.InfraNodesFilter
	isdFilter       *whitelist_filters.ISDFilter
	neighbourFilter *whitelist_filters.NeighbourFilter
	upFilter        *whitelist_filters.NeighbourFilter
	downFilter      *whitelist_filters.NeighbourFilter
	coreFilter      *whitelist_filters.NeighbourFilter
	//Interval request limit filters
	intIntervalFilter *per_as_rate_limiting.RateLimitFilter
	extIntervalFilter *per_as_rate_limiting.RateLimitFilter
)

func Init(locIA addr.IA, config *FilterHandlerConfig, path string) error {
	localIA = locIA
	pathToTopoFile = path
	cfg = config
	cfg.InitDefaults()
	if err := cfg.Validate(); err != nil {
		return err
	}
	return nil
}

var _ infra.Handler = (*FilterHandler)(nil)

type FilterHandler struct {
	internalFilters []filters.InternalFilter
	externalFilters []filters.ExternalFilter
	originalHandler infra.Handler
}

func (h *FilterHandler) Handle(r *infra.Request) *infra.HandlerResult {
	address := r.Peer.(*snet.Addr)
	if address.IA == localIA {
		for _, f := range h.internalFilters {
			if result, err := f.FilterInternal(*address); result != filters.FilterAccept {
				errSendingAck := sendErrorAck(r)
				if err != nil || errSendingAck {
					return infra.MetricsErrInternal
				}
				return infra.MetricsResultOk
			}
		}
	} else {
		for _, f := range h.externalFilters {
			if result, err := f.FilterExternal(*address); result != filters.FilterAccept {
				errSendingAck := sendErrorAck(r)
				if err != nil || errSendingAck {
					return infra.MetricsErrInternal
				}
				return infra.MetricsResultOk
			}
		}
	}
	return h.originalHandler.Handle(r)
}

func sendErrorAck(r *infra.Request) bool {
	ctx := r.Context()
	logger := log.FromCtx(ctx)
	rwriter, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("No response writer found")
		return true
	}
	err := rwriter.SendAckReply(ctx, &ack.Ack{
		Err:     proto.Ack_ErrCode_reject,
		ErrDesc: "Filter reject",
	})
	if err != nil {
		return false
	}
	return true
}

func New(messageType infra.MessageType, originalHandler infra.Handler) infra.Handler {
	if rcfg, present := cfg.RequestConfigs[messageType.String()]; present {
		iFilters := make([]filters.InternalFilter, 0)
		eFilters := make([]filters.ExternalFilter, 0)
		if rcfg.InternalWL != Nothing {
			iFilters = append(iFilters, newInternalWLFilter(rcfg.InternalWL))
		}
		if rcfg.ExternalWL != Nothing {
			eFilters = append(eFilters, newExternalWLFilter(rcfg.ExternalWL))
		}
		if rcfg.InternalRateLimit != Nothing {
			iFilters = append(iFilters, newInternalRLFilter(rcfg.InternalRateLimit))
		}
		if rcfg.ExternalRateLimit != Nothing {
			eFilters = append(eFilters, newExternalRLFilter(rcfg.ExternalRateLimit))
		}
		return &FilterHandler{
			internalFilters: iFilters,
			externalFilters: eFilters,
			originalHandler: originalHandler,
		}
	}
	return originalHandler
}

func newInternalWLFilter(setting string) filters.InternalFilter {
	switch setting {
	case InfraWL:
		if infraFilter == nil {
			infraFilter = whitelist_filters.NewInfraNodesFilter(pathToTopoFile,
				cfg.WhitelistRescanning.Infra.Duration)
		}
		return infraFilter
	default:
		return &whitelist_filters.DroppingFilter{}
	}
}

func newExternalWLFilter(setting string) filters.ExternalFilter {
	switch setting {
	case ISDWL:
		if isdFilter == nil {
			isdFilter = &whitelist_filters.ISDFilter{Isd: localIA.I}
		}
		return isdFilter
	case NeighboursWL:
		if neighbourFilter == nil {
			neighbourFilter = whitelist_filters.NewNeighbourFilter(pathToTopoFile,
				cfg.WhitelistRescanning.Neighbours.Duration)
		}
		return neighbourFilter
	case UpWL:
		if upFilter == nil {
			upFilter = whitelist_filters.NewUpNeighbourFilter(pathToTopoFile,
				cfg.WhitelistRescanning.Up.Duration)
		}
		return upFilter
	case DownWL:
		if downFilter == nil {
			downFilter = whitelist_filters.NewDownNeighbourFilter(pathToTopoFile,
				cfg.WhitelistRescanning.Down.Duration)
		}
		return downFilter
	case CoreWL:
		if coreFilter == nil {
			coreFilter = whitelist_filters.NewCoreNeighbourFilter(pathToTopoFile,
				cfg.WhitelistRescanning.Core.Duration)
		}
		return coreFilter
	default:
		return &whitelist_filters.DroppingFilter{}
	}
}

func newInternalRLFilter(setting string) filters.InternalFilter {
	switch setting {
	default:
		if intIntervalFilter == nil {
			intIntervalFilter, _ = per_as_rate_limiting.FilterFromConfig(cfg.IntervalRequestLimiting.Internal)
		}
		return intIntervalFilter
	}
}

func newExternalRLFilter(setting string) filters.ExternalFilter {
	switch setting {
	default:
		if extIntervalFilter == nil {
			extIntervalFilter, _ = per_as_rate_limiting.FilterFromConfig(cfg.IntervalRequestLimiting.External)
		}
		return extIntervalFilter
	}
}
