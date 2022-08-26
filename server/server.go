package server

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/cybercryptio/go-kmip/proto"
	"github.com/cybercryptio/go-kmip/ttlv"
)

// Error enhances error with "Result Reason" field
//
// Any Error instance is returned back to the caller with message and
// result reason set, any other Go error is returned as "General Failure"
type Error interface {
	error
	ResultReason() ttlv.Enum
}

type protocolError struct {
	error
	reason ttlv.Enum
}

func (e protocolError) ResultReason() ttlv.Enum {
	return e.reason
}

func WrapError(err error, reason ttlv.Enum) protocolError {
	return protocolError{err, reason}
}

// DefaultServerTLSConfig fills in good defaults for server TLS configuration
func DefaultServerTLSConfig(config *tls.Config) {
	config.MinVersion = tls.VersionTLS12
	config.PreferServerCipherSuites = true
	config.ClientAuth = tls.RequireAndVerifyClientCert
}

// Server implements core KMIP server
type Server struct {
	// Listen address
	Addr string

	// TLS Configuration for the server
	TLSConfig *tls.Config

	// Log destination (if not set, log is discarded)
	Log *log.Logger

	// Supported version of KMIP, in the order of the preference
	//
	// If not set, defaults to DefaultSupportedVersions
	SupportedVersions []proto.ProtocolVersion

	// Network read & write timeouts
	//
	// If set to zero, timeouts are not enforced
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// SessionAuthHandler is called after TLS handshake
	//
	// This handler might additionally verify client TLS cert or perform
	// any other kind of auth (say, by soure address)
	SessionAuthHandler func(conn net.Conn) (sessionAuth interface{}, err error)

	// RequestAuthHandler is called for any request which has Authentication field set
	//
	// Value returned from RequestAuthHandler is stored as RequestContext.RequestAuth, which
	// can be used to authorize each batch item in the request
	RequestAuthHandler func(sesssion *SessionContext, auth *proto.Authentication) (requestAuth interface{}, err error)

	l        net.Listener
	mu       sync.Mutex
	wg       sync.WaitGroup
	doneChan chan struct{}
	handlers map[ttlv.Enum]Handler
}

// Handler processes specific KMIP operation
type Handler func(req *RequestContext, item *proto.RequestBatchItem) (resp interface{}, err error)

// SessionContext is initialized for each connection
type SessionContext struct {
	// Unique session identificator
	SessionID string

	// Additional opaque data related to connection auth, as returned by Server.SessionAuthHandler
	SessionAuth interface{}
}

// RequestContext covers batch of requests
type RequestContext struct {
	SessionContext

	// RequestAuth captures result of request authentication
	RequestAuth interface{}
}

// ListenAndServe creates TLS listening socket and calls Serve
//
// Channel initializedCh will be closed when listener is initialized
// (or fails to be initialized)
func (s *Server) ListenAndServe(initializedCh chan struct{}) error {
	addr := s.Addr
	if addr == "" {
		addr = ":5696"
	}

	l, err := tls.Listen("tcp", addr, s.TLSConfig)
	if err != nil {
		close(initializedCh)
		return err
	}

	return s.Serve(l, initializedCh)
}

// Serve starts accepting and serving KMIP connection on a given listener
//
// Channel initializedCh will be closed when listener is initialized
// (or fails to be initialized)
func (s *Server) Serve(l net.Listener, initializedCh chan struct{}) error {
	s.mu.Lock()
	s.l = l

	if s.Log == nil {
		s.Log = log.New(io.Discard, "", log.LstdFlags)
	}

	if len(s.SupportedVersions) == 0 {
		s.SupportedVersions = append([]proto.ProtocolVersion(nil), DefaultSupportedVersions...)
	}

	if s.handlers == nil {
		s.initHandlers()
	}
	s.mu.Unlock()

	close(initializedCh)

	defer l.Close()

	lastSession := uint32(0)

	var tempDelay time.Duration

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.getDoneChan():
				return nil
			default:
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				s.Log.Printf("[ERROR] Accept error: %s, retrying in %s", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			return err
		}

		lastSession++
		tempDelay = 0

		s.wg.Add(1)
		go s.serve(conn, fmt.Sprintf("%08x", lastSession))
	}
}

// Shutdown performs graceful shutdown of KMIP server waiting for connections to be closed
//
// Context might be used to limit time to wait for draining complete
func (s *Server) Shutdown(ctx context.Context) error {
	close(s.getDoneChan())

	s.mu.Lock()
	if s.l != nil {
		s.l.Close()
		s.l = nil
	}
	s.mu.Unlock()

	waitGroupDone := make(chan struct{})

	go func() {
		s.wg.Wait()
		close(waitGroupDone)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitGroupDone:
		return nil
	}
}

// Handle register handler for operation
//
// Server provides default handler for DISCOVER_VERSIONS operation, any other
// operation should be specifically enabled via Handle
func (s *Server) Handle(operation ttlv.Enum, handler Handler) {
	if s.handlers == nil {
		s.initHandlers()
	}

	s.handlers[operation] = handler
}

func (s *Server) initHandlers() {
	s.handlers = make(map[ttlv.Enum]Handler)
	s.handlers[ttlv.OPERATION_DISCOVER_VERSIONS] = s.handleDiscoverVersions
}

func (s *Server) getDoneChan() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.doneChan == nil {
		s.doneChan = make(chan struct{})
	}

	return s.doneChan
}

func (s *Server) serve(conn net.Conn, session string) {
	defer s.wg.Done()
	defer func() {
		s.Log.Printf("[INFO] [%s] Closed connection from %s", session, conn.RemoteAddr().String())
		conn.Close()
	}()

	s.Log.Printf("[INFO] [%s] New connection from %s", session, conn.RemoteAddr().String())

	sessionCtx := &SessionContext{
		SessionID: session,
	}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if s.ReadTimeout != 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		if s.WriteTimeout != 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		if err := tlsConn.Handshake(); err != nil {
			s.Log.Printf("[ERROR] [%s] Error in TLS handshake: %s", session, err)
			return
		}
	}

	s.mu.Lock()
	sessionAuthHandler := s.SessionAuthHandler
	s.mu.Unlock()

	if sessionAuthHandler != nil {
		var err error

		sessionCtx.SessionAuth, err = sessionAuthHandler(conn)
		if err != nil {
			s.Log.Printf("[ERROR] [%s] Error in session auth handler: %s", session, err)
			return
		}
	}

	d := ttlv.NewDecoder(conn)
	e := ttlv.NewEncoder(conn)

	for {
		var req = &proto.Request{}

		if s.ReadTimeout != 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}

		err := d.Decode(req)
		if err == io.EOF {
			break
		}

		if err != nil {
			s.Log.Printf("[ERROR] [%s] Error decoding KMIP message: %s", session, err)
			break
		}

		var resp *proto.Response
		resp, err = s.handleBatch(sessionCtx, req)
		if err != nil {
			s.Log.Printf("[ERROR] [%s] Fatal error handling batch: %s", session, err)
			break
		}

		if s.WriteTimeout != 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		err = e.Encode(resp)
		if err != nil {
			s.Log.Printf("[ERROR] [%s] Error encoding KMIP response: %s", session, err)
		}
	}
}

func (s *Server) handleBatch(session *SessionContext, req *proto.Request) (*proto.Response, error) {
	if int(req.Header.BatchCount) != len(req.BatchItems) {
		return nil, errors.Errorf("request batch count doesn't match number of batch items: %d != %d", req.Header.BatchCount, len(req.BatchItems))
	}

	if req.Header.AsynchronousIndicator {
		return nil, errors.New("asynchnronous requests are not supported")
	}

	resp := &proto.Response{
		Header: proto.ResponseHeader{
			Version:                req.Header.Version,
			TimeStamp:              time.Now(),
			ClientCorrelationValue: req.Header.ClientCorrelationValue,
			BatchCount:             req.Header.BatchCount,
		},
		BatchItems: make([]proto.ResponseBatchItem, req.Header.BatchCount),
	}

	requestCtx := &RequestContext{
		SessionContext: *session,
	}

	if req.Header.Authentication.CredentialType != 0 {
		if s.RequestAuthHandler == nil {
			return nil, errors.New("request has authentication set, but no auth handler configured")
		}
		requestAuth, err := s.RequestAuthHandler(session, &req.Header.Authentication)
		if err != nil {
			return nil, errors.Wrap(err, "error running auth handler")
		}
		requestCtx.RequestAuth = requestAuth
	}

	for i := range req.BatchItems {
		resp.BatchItems[i].Operation = req.BatchItems[i].Operation
		resp.BatchItems[i].UniqueID = append([]byte(nil), req.BatchItems[i].UniqueID...)

		batchResp, batchErr := s.handleWrapped(requestCtx, &req.BatchItems[i])
		if batchErr != nil {
			s.Log.Printf("[WARN] [%s] Request failed, operation %v: %s", requestCtx.SessionID, ttlv.OperationMap[req.BatchItems[i].Operation], batchErr)

			resp.BatchItems[i].ResultStatus = ttlv.RESULT_STATUS_OPERATION_FAILED
			// TODO: should we skip returning error message? or return it only for specific errors?
			resp.BatchItems[i].ResultMessage = batchErr.Error()
			if protoErr, ok := batchErr.(Error); ok {
				resp.BatchItems[i].ResultReason = protoErr.ResultReason()
			} else {
				resp.BatchItems[i].ResultReason = ttlv.RESULT_REASON_GENERAL_FAILURE
			}
		} else {
			s.Log.Printf("[INFO] [%s] Request processed, operation %v", requestCtx.SessionID, ttlv.OperationMap[req.BatchItems[i].Operation])
			resp.BatchItems[i].ResultStatus = ttlv.RESULT_STATUS_SUCCESS
			resp.BatchItems[i].ResponsePayload = batchResp
		}
	}

	return resp, nil
}

func (s *Server) handleWrapped(request *RequestContext, item *proto.RequestBatchItem) (resp interface{}, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errors.Errorf("panic: %s", p)

			buf := make([]byte, 8192)
			n := runtime.Stack(buf, false)
			s.Log.Printf("[ERROR] [%s] Panic in request handler, operation %s: %s", request.SessionID, ttlv.OperationMap[item.Operation], string(buf[:n]))
		}
	}()

	handler := s.handlers[item.Operation]
	if handler == nil {
		return nil, WrapError(errors.New("operation not supported"), ttlv.RESULT_REASON_OPERATION_NOT_SUPPORTED)
	}

	return handler(request, item)
}

func (s *Server) handleDiscoverVersions(req *RequestContext, item *proto.RequestBatchItem) (interface{}, error) {
	request, ok := item.RequestPayload.(proto.DiscoverVersionsRequest)
	if !ok {
		return nil, WrapError(errors.New("wrong request body"), ttlv.RESULT_REASON_INVALID_MESSAGE)
	}

	// return all the versions
	if len(request.ProtocolVersions) == 0 {
		return proto.DiscoverVersionsResponse{ProtocolVersions: s.SupportedVersions}, nil
	}

	// find matching versions
	response := proto.DiscoverVersionsResponse{}
	for _, version := range request.ProtocolVersions {
		for _, v := range s.SupportedVersions {
			if version == v {
				response.ProtocolVersions = append(response.ProtocolVersions, v)
				break
			}
		}
	}

	return response, nil
}

// DefaultSupportedVersions is a default list of supported KMIP versions
var DefaultSupportedVersions = []proto.ProtocolVersion{
	{Major: 1, Minor: 4},
	{Major: 1, Minor: 3},
	{Major: 1, Minor: 2},
	{Major: 1, Minor: 1},
}
