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
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/filter_handler"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/interval_request_limiting"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/path_length"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/request_filters/whitelisting"
	"github.com/scionproto/scion/go/lib/infra/transport"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

const (
	ResultDir = "./go/integration/filter_results"
	ConfigDir = "./go/integration/filter_configs"
)

type Result string

const (
	Pass         Result = "pass"
	Whitelist    Result = "whitelist"
	RequestLimit Result = "intervalRL"
	PathLength   Result = "pathlength"
	SegLength    Result = "seglength"
)

var (
	remote         snet.Addr
	resultFileName string
	topoFilePath   string
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.LogPanicAndExit()
	defer log.Flush()
	addFlags()
	integration.Setup()
	validateFlags()
	if integration.Mode == integration.ModeServer {
		server{}.run()
		return 0
	} else {
		return client{}.run()
	}
}

func addFlags() {
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
	flag.StringVar(&resultFileName, "results", "",
		"(Mandatory for clients) Name of the result file in "+ResultDir)
	flag.StringVar(&topoFilePath, "topoFilePath", "",
		"(Mandatory for servers) Path to the topology file of the server")
}

func validateFlags() {
	if integration.Mode == integration.ModeClient {
		if remote.Host == nil {
			integration.LogFatal("Missing remote address")
		}
		if remote.Host.L4 == nil {
			integration.LogFatal("Missing remote port")
		}
		if remote.Host.L4.Port() == 0 {
			integration.LogFatal("Invalid remote port", "remote port", remote.Host.L4.Port())
		}
		if resultFileName == "" {
			integration.LogFatal("Missing results file")
		}
	}
}

type server struct {
	conn snet.Conn
}

func (s server) run() {
	conn, err := snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", conn.LocalAddr().(*snet.Addr).Host.L4.Port())
		fmt.Printf("%s%s\n", libint.ReadySignal, integration.Local.IA)
	}

	//init the messenger
	msgr := messenger.New(
		&messenger.Config{
			IA: integration.Local.IA,
			Dispatcher: disp.New(
				transport.NewPacketTransport(conn),
				messenger.DefaultAdapter,
				log.Root(),
			),
			AddressRewriter: &messenger.AddressRewriter{
				Router: &snet.BaseRouter{IA: integration.Local.IA},
			},
		},
	)

	var cfg filter_handler.FilterHandlerConfig
	_, err = toml.DecodeFile(ConfigDir+"/"+resultFileName+".toml", &cfg)
	if err != nil {
		integration.LogFatal("Unable to decode configuration file", "err", err)
	}
	cfg.InitDefaults()
	err = cfg.Validate()
	if err != nil {
		integration.LogFatal("Error validating the configuration file", "err", err)
	}

	log.Debug(fmt.Sprintf("%v", cfg))

	err = filter_handler.Init(integration.Local.IA, &cfg, topoFilePath)

	//add handlers to the messenger
	msgr.AddHandler(infra.TRCRequest,
		filter_handler.New(infra.TRCRequest, newAcceptingHandler()))
	msgr.AddHandler(infra.ChainRequest,
		filter_handler.New(infra.ChainRequest, newAcceptingHandler()))
	log.Debug("Listening", "local", conn.LocalAddr())
	//listen and serve with messenger
	msgr.ListenAndServe()
}

func newAcceptingHandler() infra.Handler {
	return infra.HandlerFunc(func(r *infra.Request) *infra.HandlerResult {
		ctx := r.Context()
		logger := log.FromCtx(ctx)
		rwriter, ok := infra.ResponseWriterFromContext(ctx)
		if !ok {
			logger.Error("No response writer found")
			return infra.MetricsErrInternal
		}
		rwriter.SendAckReply(ctx, &ack.Ack{
			Err:     proto.Ack_ErrCode_ok,
			ErrDesc: "Passed filters",
		})
		return infra.MetricsResultOk
	})
}

type client struct {
	conn snet.Conn
	msgr infra.Messenger
}

type requestSequence struct {
	requestType        infra.MessageType
	resultType         Result
	numOfRequests      int
	maxPassingRequests int
	changingRequests   bool
}

func (c client) run() int {
	var err error

	c.conn, err = snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())

	rs, err := getRequestSequences()
	log.Debug("request sequences", "sequence", rs)
	if err != nil {
		integration.LogFatal("Unable to retrieve expected result", "err", err)
	}

	c.msgr = messenger.New(
		&messenger.Config{
			IA: integration.Local.IA,
			Dispatcher: disp.New(
				transport.NewPacketTransport(c.conn),
				messenger.DefaultAdapter,
				log.Root(),
			),
			AddressRewriter: &messenger.AddressRewriter{
				Router: &snet.BaseRouter{IA: integration.Local.IA},
			},
		},
	)

	for _, r := range rs {
		if c.requestRepeatedly(r) > 0 {
			return 1
		}
	}
	return 0
}

func (c client) requestRepeatedly(rs requestSequence) int {
	var counter = 0
	var expectingError = false
	trc := rs.requestType == infra.TRCRequest
	for i := 0; i < rs.numOfRequests; i++ {
		var err error
		if trc {
			err = c.requestTRC()
		} else {
			err = c.requestCert()
		}

		infraErr, ok := err.(*infra.Error)
		if !ok {
			log.Error(fmt.Sprintf("Error sending TRC request: Expected error of type infra.Error but got %t", err))
			return 1
		}

		if infraErr.Message.Err == proto.Ack_ErrCode_ok {
			if !expectingError {
				counter++
			} else {
				log.Debug(fmt.Sprintf("Received %v errors of type %v from %s", counter, rs.resultType, remote.IA))
				expectingError = !expectingError
				counter = 1
			}
		} else if infraErr.Message.Err == proto.Ack_ErrCode_reject {
			if rs.resultType == Whitelist && infraErr.Error() != whitelisting.ErrMsg {
				log.Error("Expected whitelisting error but got", err, infraErr)
			} else if rs.resultType == RequestLimit && infraErr.Error() != interval_request_limiting.ErrMsg {
				log.Error("Expected request limit error but got", err, infraErr)
			} else if rs.resultType == PathLength && infraErr.Error() != path_length.PathLengthOneErrMsg {
				log.Error("Expected path length error but got", err, infraErr)
			} else if rs.resultType == SegLength && infraErr.Error() != path_length.SegmentNumErrMsg {
				log.Error("Expected segment length error but got", err, infraErr)
			}

			if expectingError {
				counter++
			} else {
				if limitViolated(counter, rs.maxPassingRequests, infraErr) {
					return 1
				}
				expectingError = !expectingError
				counter = 1
			}
		} else {
			log.Error("Expected error of type ack or reject but got", "type", infraErr.Message.Err)
			return 1
		}
		if rs.changingRequests {
			trc = !trc
		}
	}

	if rs.numOfRequests == rs.maxPassingRequests {
		if counter < rs.maxPassingRequests-1 {
			log.Error("All requests for this client should have passed")
			return 1
		}
		log.Debug(fmt.Sprintf("Received %v ok(s) from %s - (no limit)", counter, remote.IA))
		log.Debug(fmt.Sprintf("Successfully sent %v requests", rs.numOfRequests))
		return 0
	}

	if expectingError {
		log.Debug(fmt.Sprintf("Received %v errors of type %v from %s", counter, rs.resultType, remote.IA))
		if rs.numOfRequests > 1 && counter == rs.numOfRequests-1 {
			log.Error("All requests were rejected")
			return 1
		}
	} else if limitViolated(counter, rs.maxPassingRequests, nil) {
		return 1
	}

	log.Debug(fmt.Sprintf("Successfully sent %v requests", rs.numOfRequests))
	return 0
}

func (c client) requestTRC() error {
	req := &cert_mgmt.TRCReq{
		CacheOnly: false,
		ISD:       remote.IA.I,
		Version:   scrypto.LatestVer,
	}
	//log.Info("Request to Server: TRC request", "remote", remote.IA)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()

	_, err := c.msgr.GetTRC(ctx, req, &remote, messenger.NextId())
	return err
}

func (c client) requestCert() error {
	req := &cert_mgmt.ChainReq{
		CacheOnly: false,
		RawIA:     remote.IA.IAInt(),
		Version:   scrypto.LatestVer,
	}
	//log.Info("Request to Server: Chain request", "remote", remote.IA)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()

	_, err := c.msgr.GetCertChain(ctx, req, &remote, messenger.NextId())
	return err
}

func limitViolated(counter, maxRequests int, errorType *infra.Error) bool {
	if counter > maxRequests {
		log.Error(fmt.Sprintf("Received %v ok messages from %s, which is over the limit (%v)",
			counter, remote.IA, maxRequests))
		return true
	}
	if counter == 0 {
		if maxRequests == 0 {
			return false
		}
		log.Error(fmt.Sprintf("Expected ok message from %s but got '%v' error instead",
			remote.IA, errorType))
		return true
	}
	log.Debug(fmt.Sprintf("Received %v ok(s) from %s - (limit %v)", counter, remote.IA, maxRequests))
	return false
}

func getRequestSequences() ([]requestSequence, error) {
	configFile, err := os.Open(ResultDir + "/" + resultFileName)
	if err != nil {
		return []requestSequence{}, err
	}
	defer configFile.Close()

	localIAString := integration.Local.IA.String()
	remoteIAString := remote.IA.String()

	var result []requestSequence

	scanner := bufio.NewScanner(configFile)
	for scanner.Scan() {
		resultParams := strings.Fields(scanner.Text())
		if len(resultParams) == 0 || strings.HasPrefix(resultParams[0], "//") {
			continue
		} else if resultParams[0] == localIAString && resultParams[1] == remoteIAString {
			rs, err := parseResultInfo(resultParams[2:])
			if err != nil {
				return []requestSequence{}, err
			}
			result = append(result, rs)
		}
	}
	if err := scanner.Err(); err != nil {
		return []requestSequence{}, err
	}
	if len(result) == 0 {
		return []requestSequence{}, common.NewBasicError(
			fmt.Sprintf("Did not find a result type for local IA %v and remote IA %v",
				localIAString, remoteIAString), nil)
	}
	return result, nil
}

func parseResultInfo(resultParams []string) (requestSequence, error) {
	var requestType infra.MessageType
	changingRequests := false
	if resultParams[0] == "Changing" {
		changingRequests = true
		requestType = infra.TRCRequest
	} else if resultParams[0] == infra.TRCRequest.String() {
		requestType = infra.TRCRequest
	} else if resultParams[0] == infra.ChainRequest.String() {
		requestType = infra.ChainRequest
	} else {
		integration.LogFatal("Unknown request type", "requestType", resultParams[0])
	}
	result := Result(resultParams[1])
	var numOfRequests = 1
	var numOfSuccessfulRequests = 0
	if result == Pass {
		numOfSuccessfulRequests = 1
	}
	var err error

	if len(resultParams) > 2 {
		infoParams := strings.Split(resultParams[2], ",")
		req, err1 := strconv.ParseInt(infoParams[0], 10, 32)
		if err1 != nil {
			err = err1
		} else {
			sucReq, err2 := strconv.ParseInt(infoParams[1], 10, 32)
			if err2 != nil {
				err = err2
			} else {
				numOfRequests = int(req)
				numOfSuccessfulRequests = int(sucReq)
			}
		}
	}

	return requestSequence{requestType, result,
		numOfRequests, numOfSuccessfulRequests, changingRequests}, err
}
