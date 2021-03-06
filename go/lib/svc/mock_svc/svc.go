// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/lib/svc (interfaces: Prechecker,RequestHandler,RoundTripper)

// Package mock_svc is a generated GoMock package.
package mock_svc

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	overlay "github.com/scionproto/scion/go/lib/overlay"
	snet "github.com/scionproto/scion/go/lib/snet"
	svc "github.com/scionproto/scion/go/lib/svc"
	reflect "reflect"
)

// MockPrechecker is a mock of Prechecker interface
type MockPrechecker struct {
	ctrl     *gomock.Controller
	recorder *MockPrecheckerMockRecorder
}

// MockPrecheckerMockRecorder is the mock recorder for MockPrechecker
type MockPrecheckerMockRecorder struct {
	mock *MockPrechecker
}

// NewMockPrechecker creates a new mock instance
func NewMockPrechecker(ctrl *gomock.Controller) *MockPrechecker {
	mock := &MockPrechecker{ctrl: ctrl}
	mock.recorder = &MockPrecheckerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockPrechecker) EXPECT() *MockPrecheckerMockRecorder {
	return m.recorder
}

// Precheck mocks base method
func (m *MockPrechecker) Precheck(arg0 *snet.SCIONPacket) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Precheck", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Precheck indicates an expected call of Precheck
func (mr *MockPrecheckerMockRecorder) Precheck(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Precheck", reflect.TypeOf((*MockPrechecker)(nil).Precheck), arg0)
}

// MockRequestHandler is a mock of RequestHandler interface
type MockRequestHandler struct {
	ctrl     *gomock.Controller
	recorder *MockRequestHandlerMockRecorder
}

// MockRequestHandlerMockRecorder is the mock recorder for MockRequestHandler
type MockRequestHandlerMockRecorder struct {
	mock *MockRequestHandler
}

// NewMockRequestHandler creates a new mock instance
func NewMockRequestHandler(ctrl *gomock.Controller) *MockRequestHandler {
	mock := &MockRequestHandler{ctrl: ctrl}
	mock.recorder = &MockRequestHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRequestHandler) EXPECT() *MockRequestHandlerMockRecorder {
	return m.recorder
}

// Handle mocks base method
func (m *MockRequestHandler) Handle(arg0 *snet.SCIONPacket, arg1 *overlay.OverlayAddr) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Handle", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Handle indicates an expected call of Handle
func (mr *MockRequestHandlerMockRecorder) Handle(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Handle", reflect.TypeOf((*MockRequestHandler)(nil).Handle), arg0, arg1)
}

// MockRoundTripper is a mock of RoundTripper interface
type MockRoundTripper struct {
	ctrl     *gomock.Controller
	recorder *MockRoundTripperMockRecorder
}

// MockRoundTripperMockRecorder is the mock recorder for MockRoundTripper
type MockRoundTripperMockRecorder struct {
	mock *MockRoundTripper
}

// NewMockRoundTripper creates a new mock instance
func NewMockRoundTripper(ctrl *gomock.Controller) *MockRoundTripper {
	mock := &MockRoundTripper{ctrl: ctrl}
	mock.recorder = &MockRoundTripperMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRoundTripper) EXPECT() *MockRoundTripperMockRecorder {
	return m.recorder
}

// RoundTrip mocks base method
func (m *MockRoundTripper) RoundTrip(arg0 context.Context, arg1 snet.PacketConn, arg2 *snet.SCIONPacket, arg3 *overlay.OverlayAddr) (*svc.Reply, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RoundTrip", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*svc.Reply)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RoundTrip indicates an expected call of RoundTrip
func (mr *MockRoundTripperMockRecorder) RoundTrip(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RoundTrip", reflect.TypeOf((*MockRoundTripper)(nil).RoundTrip), arg0, arg1, arg2, arg3)
}
