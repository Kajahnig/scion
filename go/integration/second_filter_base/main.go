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

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/transport"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

const (
	ResultDir = "./go/integration/filter_results"
)

type Result string
type RequestType string

const (
	Whitelist  Result = "whitelist"
	Pathlength Result = "pathLength"

	TRCReq   RequestType = "TRCReq"
	ChainReq RequestType = "ChainReq"
)

var (
	remote         snet.Addr
	resultFileName string
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
	//Todo add the config file flag here so the server can use it to make handlers,
	// or actually just use the resultFileName, should be the same anyway
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
	msgr infra.Messenger
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
		},
	)
	//TODO, parse the config for the firewall filters and set up handlers according to that

	//add handlers to the messenger
	msgr.AddHandler(infra.TRCRequest, newHandler(proto.Ack_ErrCode_ok, Whitelist))
	msgr.AddHandler(infra.ChainRequest, newHandler(proto.Ack_ErrCode_reject, Pathlength))
	log.Debug("Listening", "local", conn.LocalAddr())
	//listen and serve with messenger
	msgr.ListenAndServe()
}

func newHandler(errorCode proto.Ack_ErrCode, reason Result) infra.Handler {
	return infra.HandlerFunc(func(r *infra.Request) *infra.HandlerResult {
		ctx := r.Context()
		logger := log.FromCtx(ctx)
		rwriter, ok := infra.ResponseWriterFromContext(ctx)
		if !ok {
			logger.Error("No response writer found")
			return infra.MetricsErrInternal
		}
		rwriter.SendAckReply(ctx, &ack.Ack{
			Err:     errorCode,
			ErrDesc: string(reason),
		})
		return infra.MetricsResultOk
	})
}

type client struct {
	conn               snet.Conn
	msgr               infra.Messenger
	requestType        RequestType
	resultType         Result
	numOfRequests      int
	maxPassingRequests int
}

type requestSeries struct {
	requestType        RequestType
	resultType         Result
	numOfRequests      int
	maxPassingRequests int
}

func (c client) run() int {
	var err error

	c.conn, err = snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())

	rs, err := getRequestSequences()
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
		},
	)

	for _, r := range rs {
		if c.sendRequestSeries(r) > 0 {
			return 1
		}
	}
	return 0
}

func (c client) sendRequestSeries(rs requestSeries) int {
	switch rs.requestType {
	case TRCReq:
		err := c.requestTRC(proto.Ack_ErrCode_ok)
		if err != nil {
			log.Info("Error in TRC request", "err", err)
			return 1
		}
		return 0
	case ChainReq:
		err := c.requestCert(proto.Ack_ErrCode_reject)
		if err != nil {
			log.Info("Error in TRC request", "err", err)
			return 1
		}
		return 0
	}
	return 1
}

func (c client) requestTRC(answer proto.Ack_ErrCode) error {
	req := &cert_mgmt.TRCReq{
		CacheOnly: false,
		ISD:       remote.IA.I,
		Version:   scrypto.LatestVer,
	}
	log.Info("Request to Server: TRC request", "remote", remote.IA)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()

	_, err := c.msgr.GetTRC(ctx, req, &remote, messenger.NextId())
	return checkError(answer, err)
}

func (c client) requestCert(answer proto.Ack_ErrCode) error {
	req := &cert_mgmt.ChainReq{
		CacheOnly: false,
		RawIA:     remote.IA.IAInt(),
		Version:   scrypto.LatestVer,
	}
	log.Info("Request to Server: Chain request", "remote", remote.IA)
	ctx, cancelF := context.WithTimeout(context.Background(), integration.DefaultIOTimeout)
	defer cancelF()

	_, err := c.msgr.GetCertChain(ctx, req, &remote, messenger.NextId())
	return checkError(answer, err)
}

func checkError(answer proto.Ack_ErrCode, err error) error {
	switch t := err.(type) {
	case *infra.Error:
		if t.Message.Err == answer {
			return nil
		} else {
			return common.NewBasicError(fmt.Sprintf("Expected %v but got %v",
				answer.String(), t.Message.Err.String()), nil)
		}
	}
	return common.NewBasicError("Expected error of type infra.Error but got", err)
}

func getRequestSequences() ([]requestSeries, error) {
	configFile, err := os.Open(ResultDir + "/" + resultFileName)
	if err != nil {
		return []requestSeries{}, err
	}
	defer configFile.Close()

	localIAString := integration.Local.IA.String()
	remoteIAString := remote.IA.String()

	var result []requestSeries

	scanner := bufio.NewScanner(configFile)
	for scanner.Scan() {
		resultParams := strings.Fields(scanner.Text())
		if len(resultParams) == 0 || strings.HasPrefix(resultParams[0], "//") {
			continue
		} else if resultParams[0] == localIAString && resultParams[1] == remoteIAString {
			rs, err := parseResultInfo(resultParams[2:])
			if err != nil {
				return []requestSeries{}, err
			}
			result = append(result, rs)
		}
	}
	if err := scanner.Err(); err != nil {
		return []requestSeries{}, err
	}
	if len(result) == 0 {
		return []requestSeries{}, common.NewBasicError(
			fmt.Sprintf("Did not find a result type for local IA %v and remote IA %v",
				localIAString, remoteIAString), nil)
	}
	return result, nil
}

func parseResultInfo(resultParams []string) (requestSeries, error) {
	requstType := RequestType(resultParams[0])
	result := Result(resultParams[1])
	var numOfRequests = 1
	var numOfSuccessfulRequests = 0
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
	return requestSeries{requstType, result,
		numOfRequests, numOfSuccessfulRequests}, err
}

/*func (c client) AttemptRepeatedly() int {
	var counter = 0
	var expectingError = false
	for i := 0; i < c.numOfRequests; i++ {
		if err := c.ping(); err != nil {
			log.Error("Could not send packet", "err", err)
			return 1
		}
		receivedError, err := c.pong(i)
		if err != nil {
			log.Debug(fmt.Sprintf("Error receiving pong %v", i), "err", err)
			return 1
		}

		if receivedError == expectingError {
			counter++
		} else {
			if c.limitViolated(expectingError, counter) {
				return 1
			}
			expectingError = !expectingError
			counter = 1
		}
	}

	if c.limitViolated(expectingError, counter) {
		return 1
	}
	if expectingError && c.numOfRequests > 1 && counter == c.numOfRequests-1 {
		log.Error("All requests were rejected")
		return 1
	}
	if c.numOfRequests == c.maxPassingRequests && counter < c.maxPassingRequests-1 {
		log.Error("All requests for this client should have passed")
		return 1
	}
	log.Debug(fmt.Sprintf("Successfully sent %v requests", c.numOfRequests))
	return 0
}*/

/*func (c client) limitViolated(expectingError bool, counter int) bool {
	if expectingError { //means we expected an error but did not get one
		log.Debug(fmt.Sprintf("Received %v errors of type %v from %s",
			counter, c.resultType.Name(scmp.C_Filtering), remote.IA))

	} else { //means we did not expect an error but we got one
		if counter > c.maxPassingRequests {
			log.Error(fmt.Sprintf("Received %v pong messages, which is over the limit (%v)",
				counter, c.maxPassingRequests))
			return true
		}
		log.Debug(fmt.Sprintf("Received %v pong(s) from %s - (limit %v)",
			counter, remote.IA, c.maxPassingRequests))
	}
	return false
}*/
