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
	"strings"
	"time"

	"github.com/scionproto/scion/go/integration/filter_integration_common"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/filters/filter_creation"
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
	filter_integration_common.SetupWithFilters()
	validateFlags()
	if filter_integration_common.Mode == filter_integration_common.ModeServer {
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
	if filter_integration_common.Mode == filter_integration_common.ModeClient {
		if remote.Host == nil {
			filter_integration_common.LogFatal("Missing remote address")
		}
		if remote.Host.L4 == nil {
			filter_integration_common.LogFatal("Missing remote port")
		}
		if remote.Host.L4.Port() == 0 {
			filter_integration_common.LogFatal("Invalid remote port", "remote port", remote.Host.L4.Port())
		}
		if resultFileName == "" {
			filter_integration_common.LogFatal("Missing results file")
		}
	}
}

type server struct {
	conn snet.Conn
}

func (s server) run() {
	conn, err := snet.ListenSCION("udp4", &filter_integration_common.Local)
	if err != nil {
		filter_integration_common.LogFatal("Error listening", "err", err)
	}
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", conn.LocalAddr().(*snet.Addr).Host.L4.Port())
		fmt.Printf("%s%s\n", libint.ReadySignal, filter_integration_common.Local.IA)
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
		if string(b[:pktLen]) != pingMessageString(filter_integration_common.Local.IA) {
			filter_integration_common.LogFatal("Received unexpected data", "data", b[:pktLen])
		}
		log.Debug(fmt.Sprintf("Ping received from %s, sending pong.", addr))
		// Send pong
		reply := pongMessage(filter_integration_common.Local.IA, addr.IA)
		_, err = conn.WriteToSCION(reply, addr)
		if err != nil {
			filter_integration_common.LogFatal("Unable to send reply", "err", err)
		}
		log.Debug(fmt.Sprintf("Sent pong to %s", addr.Desc()))
	}
}

type client struct {
	conn         snet.Conn
	sdConn       sciond.Connector
	expectsError bool
	resultType   scmp.Type
}

func (c client) run() int {
	var err error

	c.conn, err = snet.ListenSCION("udp4", &filter_integration_common.Local)
	if err != nil {
		filter_integration_common.LogFatal("Unable to listen", "err", err)
	}
	log.Debug("Send on", "local", c.conn.LocalAddr())

	c.sdConn = snet.DefNetwork.Sciond()

	c.expectsError, c.resultType, err = determineExpectedResult()
	if err != nil {
		filter_integration_common.LogFatal("Unable to retrieve expected result", "err", err)
	}

	return filter_integration_common.AttemptRepeatedly("End2End", c.attemptRequest)
}

func (c client) attemptRequest(n int) bool {
	// Send ping
	if err := c.ping(n); err != nil {
		log.Error("Could not send packet", "err", err)
		return false
	}
	// Receive pong
	if err := c.pong(); err != nil {
		log.Debug("Error receiving pong", "err", err)
		return false
	}
	return true
}

func (c client) ping(n int) error {
	if err := c.getRemote(n); err != nil {
		return err
	}
	c.conn.SetWriteDeadline(time.Now().Add(filter_integration_common.DefaultIOTimeout))
	b := pingMessage(remote.IA)
	_, err := c.conn.WriteTo(b, &remote)
	return err
}

func (c client) getRemote(n int) error {
	if remote.IA.Equal(filter_integration_common.Local.IA) {
		return nil
	}
	// Get paths from sciond
	ctx, cancelF := context.WithTimeout(context.Background(), libint.CtxTimeout)
	defer cancelF()
	paths, err := c.sdConn.Paths(ctx, remote.IA, filter_integration_common.Local.IA, 1,
		sciond.PathReqFlags{Refresh: n != 0})
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

func (c client) pong() error {
	c.conn.SetReadDeadline(time.Now().Add(filter_integration_common.DefaultIOTimeout))
	reply := make([]byte, 1024)
	pktLen, err := c.conn.Read(reply)

	if c.expectsError {
		//reply should be an scmp error
		return checkForExpectedSCMPError(err, c.resultType)
	} else if err != nil {
		//no error expected but one occurred
		return common.NewBasicError("Error reading packet or SCMP error received when pong was expected", err)
	}

	//no error expected and none received, so check for pong
	return checkForPongMessage(string(reply[:pktLen]))
}

func determineExpectedResult() (bool, scmp.Type, error) {
	configFile, err := os.Open(ResultDir + "/" + resultFileName)
	if err != nil {
		return false, 0, err
	}
	defer configFile.Close()

	localIAString := filter_integration_common.Local.IA.String()
	remoteIAString := remote.IA.String()

	scanner := bufio.NewScanner(configFile)
	for scanner.Scan() {
		resultParams := strings.Fields(scanner.Text())
		if resultParams[0] == localIAString &&
			resultParams[1] == remoteIAString {
			switch resultParams[2] {
			case "no":
				return false, 0, nil
			case filter_creation.Whitelist:
				return true, scmp.T_F_NotOnWhitelist, nil
			case filter_creation.PathLength:
				return true, scmp.T_F_PathLengthNotAccepted, nil
			default:
				return false, 0, common.NewBasicError("No matching result type found",
					nil, "input", resultParams[2])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, 0, err
	}
	return false, 0, common.NewBasicError(
		fmt.Sprintf("Did not find a result type for local IA %v and remote IA %v",
			localIAString, remoteIAString), nil)
}

func checkForExpectedSCMPError(err error, t scmp.Type) error {
	if err == nil {
		return common.NewBasicError("Expected an SCMP error but got none", nil)
	}
	opErr, ok := err.(*snet.OpError)
	if !ok {
		return common.NewBasicError("Expected OpError but got", err)
	}
	typeName := t.Name(FilterClass)
	if opErr.SCMP().Class == FilterClass && opErr.SCMP().Type == t {
		log.Debug(fmt.Sprintf("Received expected %v error from %s", typeName, remote.IA))
		return nil
	}
	return common.NewBasicError(
		fmt.Sprintf("Expected SCMP Filtering error of type %v but got", typeName),
		err)
}

func checkForPongMessage(reply string) error {
	expected := pongMessageString(remote.IA, filter_integration_common.Local.IA)
	if reply != expected {
		return common.NewBasicError("Received unexpected data", nil, "data",
			reply, "expected", expected)
	}
	log.Debug(fmt.Sprintf("Received pong from %s", remote.IA))
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
