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
	"time"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	ping        = "ping:"
	pong        = "pong:"
	ResultDir   = "./go/integration/filter_results"
	FilterClass = scmp.C_Filtering
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
	integration.SetupWithPacketFilters()
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
	log.Debug("Listening", "local", conn.LocalAddr())
	// Receive ping message
	b := make(common.RawBytes, 1024)
	for {
		pktLen, addr, err := conn.ReadFromSCION(b)
		if err != nil {
			log.Error("Error reading packet", "err", err)
			continue
		}
		if string(b[:pktLen]) != pingMessageString(integration.Local.IA) {
			integration.LogFatal("Received unexpected data", "data", b[:pktLen])
		}
		log.Debug(fmt.Sprintf("Ping received from %s, sending pong.", addr))
		// Send pong
		reply := pongMessage(integration.Local.IA, addr.IA)
		_, err = conn.WriteToSCION(reply, addr)
		if err != nil {
			integration.LogFatal("Unable to send reply", "err", err)
		}
		log.Debug(fmt.Sprintf("Sent pong to %s", addr.Desc()))
	}
}

type client struct {
	conn               snet.Conn
	sdConn             sciond.Connector
	numOfRequests      int
	maxPassingRequests int
	resultType         scmp.Type
}

func (c client) run() int {
	var err error

	c.conn, err = snet.ListenSCION("udp4", &integration.Local)
	if err != nil {
		integration.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())

	c.sdConn = snet.DefNetwork.Sciond()

	c.numOfRequests, c.maxPassingRequests, c.resultType, err = determineExpectedResult()
	if err != nil {
		integration.LogFatal("Unable to retrieve expected result", "err", err)
	}

	if err := c.getRemote(); err != nil {
		log.Error("Could not get remote", "err", err)
		return 1
	}

	return c.AttemptRepeatedly()
}

func determineExpectedResult() (int, int, scmp.Type, error) {
	configFile, err := os.Open(ResultDir + "/" + resultFileName)
	if err != nil {
		return 0, 0, 0, err
	}
	defer configFile.Close()

	localIAString := integration.Local.IA.String()
	remoteIAString := remote.IA.String()

	scanner := bufio.NewScanner(configFile)
	for scanner.Scan() {
		resultParams := strings.Fields(scanner.Text())
		if len(resultParams) == 0 || strings.HasPrefix(resultParams[0], "//") {
			continue
		} else if resultParams[0] == localIAString && resultParams[1] == remoteIAString {
			return parseResultInfo(resultParams[2:])
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, 0, err
	}
	return 0, 0, 0, common.NewBasicError(
		fmt.Sprintf("Did not find a result type for local IA %v and remote IA %v",
			localIAString, remoteIAString), nil)
}

func parseResultInfo(resultParams []string) (int, int, scmp.Type, error) {
	var resultType scmp.Type
	var numOfRequests = 1
	var numOfSuccessfulRequests = 0
	var err error
	switch resultParams[0] {
	case "no":
		resultType = scmp.Type(100)
		numOfSuccessfulRequests = 1
	case "drkey":
		resultType = scmp.T_F_NoDRKeyAuthentication
	default:
		err = common.NewBasicError("No matching result type found",
			nil, "input", resultParams[0])
	}
	if len(resultParams) > 1 && err == nil {
		infoParams := strings.Split(resultParams[1], ",")
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
	return numOfRequests, numOfSuccessfulRequests, resultType, err
}

func (c client) getRemote() error {
	if remote.IA.Equal(integration.Local.IA) {
		return nil
	}
	// Get paths from sciond
	ctx, cancelF := context.WithTimeout(context.Background(), libint.CtxTimeout)
	defer cancelF()
	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA, 1,
		sciond.PathReqFlags{Refresh: false})
	if err != nil {
		return common.NewBasicError("Error requesting paths", err)
	}
	if len(paths.Entries) == 0 {
		return common.NewBasicError("No path entries found", nil)
	}
	pathEntry := paths.Entries[0]
	path := spath.New(pathEntry.Path.FwdPath)
	if err = path.InitOffsets(); err != nil {
		return common.NewBasicError("Unable to initialize path", err)
	}
	// Extract forwarding path from sciond response
	remote.Path = path
	remote.NextHop, err = pathEntry.HostInfo.Overlay()
	if err != nil {
		return common.NewBasicError("Error getting overlay", err)
	}
	return nil
}

func (c client) AttemptRepeatedly() int {
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
}

func (c client) limitViolated(expectingError bool, counter int) bool {
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
}

func (c client) ping() error {
	time.Sleep(1 * time.Millisecond)
	c.conn.SetWriteDeadline(time.Now().Add(integration.DefaultIOTimeout))
	b := pingMessage(remote.IA)
	_, err := c.conn.WriteTo(b, &remote)
	return err
}

func (c client) pong(n int) (bool, error) {
	c.conn.SetReadDeadline(time.Now().Add(integration.DefaultIOTimeout))
	reply := make([]byte, 1024)
	pktLen, err := c.conn.Read(reply)

	if err != nil { //reply should be an scmp error of the specific result type
		return true, checkForExpectedSCMPError(err, c.resultType)
	}
	//no error received, so check for pong
	return false, checkForPongMessage(string(reply[:pktLen]), n)
}

func checkForExpectedSCMPError(err error, t scmp.Type) error {
	opErr, ok := err.(*snet.OpError)
	if !ok {
		return common.NewBasicError("Expected OpError but got", err)
	}
	typeName := t.Name(FilterClass)
	if opErr.SCMP().Class == FilterClass && opErr.SCMP().Type == t {
		//log.Debug(fmt.Sprintf("Received expected %v error from %s", typeName, remote.IA))
		return nil
	}
	return common.NewBasicError(
		fmt.Sprintf("Expected SCMP Filtering error of type %v but got", typeName),
		err)
}

func checkForPongMessage(reply string, n int) error {
	expected := pongMessageString(remote.IA, integration.Local.IA)
	if reply != expected {
		return common.NewBasicError("Received unexpected data", nil, "data",
			reply, "expected", expected)
	}
	//log.Debug(fmt.Sprintf("Received pong %v from %s", n, remote.IA))
	return nil
}

func pingMessage(server addr.IA) []byte {
	return []byte(pingMessageString(server))
}

func pingMessageString(server addr.IA) string {
	return ping + server.String()
}

func pongMessage(server, client addr.IA) []byte {
	return []byte(pongMessageString(server, client))
}

func pongMessageString(server, client addr.IA) string {
	return pong + server.String() + client.String()
}