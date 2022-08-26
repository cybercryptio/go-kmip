package server

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/suite"

	"github.com/cybercryptio/go-kmip/client"
	"github.com/cybercryptio/go-kmip/proto"
	"github.com/cybercryptio/go-kmip/ttlv"
)

type CertificateSet struct {
	CAKey  *ecdsa.PrivateKey
	CACert *x509.Certificate

	ServerKey  *ecdsa.PrivateKey
	ServerCert *x509.Certificate

	ClientKey  *ecdsa.PrivateKey
	ClientCert *x509.Certificate

	CAPool *x509.CertPool
}

func (set *CertificateSet) Generate(hostnames []string, ips []net.IP) error {
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.Wrapf(err, "failed to generate serial number")
	}

	set.CAKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrapf(err, "failt to generate CA key")
	}

	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &set.CAKey.PublicKey, set.CAKey)
	if err != nil {
		return errors.Wrapf(err, "error generating CA certificate")
	}

	set.CACert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing CA cert")
	}

	set.ServerKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrapf(err, "error generating server key")
	}

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.Wrapf(err, "failed to generate serial number")
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "test_cert_1",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           ips,
		DNSNames:              hostnames,
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &serverTemplate, &rootTemplate, &set.ServerKey.PublicKey, set.CAKey)
	if err != nil {
		return errors.Wrapf(err, "error generating server cert")
	}

	set.ServerCert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing server cert")
	}

	set.ClientKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrapf(err, "error generating client key")
	}

	clientTemplate := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(4),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "client_auth_test_cert",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &clientTemplate, &rootTemplate, &set.ClientKey.PublicKey, set.CAKey)
	if err != nil {
		return errors.Wrapf(err, "error generating client cert")
	}

	set.ClientCert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing client cert")
	}

	set.CAPool = x509.NewCertPool()
	set.CAPool.AddCert(set.CACert)

	return nil
}

type ServerSuite struct {
	suite.Suite

	certs  CertificateSet
	server Server
	client client.Client

	listenCh chan error
}

func (s *ServerSuite) SetupSuite() {
	s.Require().NoError(s.certs.Generate([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}))

	s.server.Addr = "localhost:"
	s.server.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	DefaultServerTLSConfig(s.server.TLSConfig)
	s.server.TLSConfig.ClientCAs = s.certs.CAPool
	s.server.TLSConfig.Certificates = []tls.Certificate{
		{
			Certificate: [][]byte{s.certs.ServerCert.Raw},
			PrivateKey:  s.certs.ServerKey,
		},
	}

	s.server.ReadTimeout = time.Second
	s.server.WriteTimeout = time.Second

	s.server.Log = log.New(os.Stderr, "[kmip] ", log.LstdFlags)

	s.listenCh = make(chan error, 1)
	initializedCh := make(chan struct{})

	go func() {
		s.listenCh <- s.server.ListenAndServe(initializedCh)
	}()

	<-initializedCh
}

func (s *ServerSuite) SetupTest() {
	s.server.mu.Lock()
	addr := s.server.l.Addr().String()
	s.server.mu.Unlock()

	_, port, err := net.SplitHostPort(addr)
	s.Require().NoError(err)

	s.client.Endpoint = "localhost:" + port
	s.client.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	client.DefaultClientTLSConfig(s.client.TLSConfig)
	s.client.TLSConfig.RootCAs = s.certs.CAPool
	s.client.TLSConfig.Certificates = []tls.Certificate{
		{
			Certificate: [][]byte{s.certs.ClientCert.Raw},
			PrivateKey:  s.certs.ClientKey,
		},
	}

	s.client.ReadTimeout = time.Second
	s.client.WriteTimeout = time.Second
}

func (s *ServerSuite) TearDownTest() {
	s.Require().NoError(s.client.Close())

	// reset server state
	s.server.mu.Lock()
	s.server.SessionAuthHandler = nil
	s.server.initHandlers()
	s.server.mu.Unlock()
}

func (s *ServerSuite) TearDownSuite() {
	ctx, ctxCancel := context.WithTimeout(context.Background(), time.Second)
	defer ctxCancel()

	s.Require().NoError(s.server.Shutdown(ctx))
	s.Require().NoError(<-s.listenCh)
}

func (s *ServerSuite) TestDiscoverVersions() {
	s.Require().NoError(s.client.Connect())

	request := proto.DiscoverVersionsRequest{
		ProtocolVersions: DefaultSupportedVersions,
	}
	versions, err := s.client.DiscoverVersions(request)
	s.Require().NoError(err)
	s.Require().Equal(proto.DiscoverVersionsResponse{ProtocolVersions: DefaultSupportedVersions}, versions)

	request = proto.DiscoverVersionsRequest{
		ProtocolVersions: nil,
	}
	versions, err = s.client.DiscoverVersions(request)
	s.Require().NoError(err)
	s.Require().Equal(proto.DiscoverVersionsResponse{ProtocolVersions: DefaultSupportedVersions}, versions)

	request = proto.DiscoverVersionsRequest{
		ProtocolVersions: []proto.ProtocolVersion{{Major: 1, Minor: 2}},
	}
	versions, err = s.client.DiscoverVersions(request)
	s.Require().NoError(err)
	s.Require().Equal(proto.DiscoverVersionsResponse{ProtocolVersions: []proto.ProtocolVersion{{Major: 1, Minor: 2}}}, versions)

	request = proto.DiscoverVersionsRequest{
		ProtocolVersions: []proto.ProtocolVersion{{Major: 2, Minor: 0}},
	}
	versions, err = s.client.DiscoverVersions(request)
	s.Require().NoError(err)
	s.Require().Equal(proto.DiscoverVersionsResponse{}, versions)
}

func (s *ServerSuite) TestSessionAuthHandlerOkay() {
	s.server.SessionAuthHandler = func(conn net.Conn) (interface{}, error) {
		commonName := conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Subject.CommonName

		if commonName != "client_auth_test_cert" {
			return nil, errors.New("wrong common name")
		}

		return commonName, nil
	}

	s.server.Handle(ttlv.OPERATION_DISCOVER_VERSIONS, func(req *RequestContext, item *proto.RequestBatchItem) (interface{}, error) {
		if req.SessionAuth.(string) != "client_auth_test_cert" {
			return nil, errors.New("wrong session auth")
		}

		return proto.DiscoverVersionsResponse{
			ProtocolVersions: nil,
		}, nil
	})

	s.Require().NoError(s.client.Connect())

	versions, err := s.client.DiscoverVersions(proto.DiscoverVersionsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(proto.DiscoverVersionsResponse{}, versions)
}

func (s *ServerSuite) TestSessionAuthHandlerFail() {
	s.server.SessionAuthHandler = func(conn net.Conn) (interface{}, error) {
		commonName := conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Subject.CommonName

		if commonName != "xxx" {
			return nil, errors.New("wrong common name")
		}

		return commonName, nil
	}

	s.Require().NoError(s.client.Connect())

	_, err := s.client.DiscoverVersions(proto.DiscoverVersionsRequest{})
	s.Require().Regexp("(broken pipe|EOF)$", errors.Cause(err).Error())

	s.client.Close()
}

func (s *ServerSuite) TestConnectTLSNoCert() {
	var savedCerts []tls.Certificate
	savedCerts, s.client.TLSConfig.Certificates = s.client.TLSConfig.Certificates, nil
	defer func() {
		s.client.TLSConfig.Certificates = savedCerts
	}()

	err := s.client.Connect()
	if err != nil {
		s.Require().EqualError(errors.Cause(err), "remote error: tls: bad certificate")
	} else {
		_, err = s.client.DiscoverVersions(proto.DiscoverVersionsRequest{})

		s.Require().Error(err)
	}

	s.client.Close() //nolint:errcheck
}

func (s *ServerSuite) TestConnectTLSNoCA() {
	var savedPool *x509.CertPool
	savedPool, s.client.TLSConfig.RootCAs = s.client.TLSConfig.RootCAs, nil
	defer func() {
		s.client.TLSConfig.RootCAs = savedPool
	}()

	err := s.client.Connect()
	s.Require().Error(err)
}

func (s *ServerSuite) TestOperationGenericFail() {
	s.server.Handle(ttlv.OPERATION_DISCOVER_VERSIONS, func(req *RequestContext, item *proto.RequestBatchItem) (interface{}, error) {
		return nil, errors.New("oops!")
	})

	s.Require().NoError(s.client.Connect())

	_, err := s.client.DiscoverVersions(proto.DiscoverVersionsRequest{})
	s.Require().EqualError(errors.Cause(err), "oops!")
	s.Require().Equal(errors.Cause(err).(Error).ResultReason(), ttlv.RESULT_REASON_GENERAL_FAILURE)
}

func (s *ServerSuite) TestOperationPanic() {
	s.server.Handle(ttlv.OPERATION_DISCOVER_VERSIONS, func(req *RequestContext, item *proto.RequestBatchItem) (interface{}, error) {
		panic("oops!")
	})

	s.Require().NoError(s.client.Connect())

	_, err := s.client.DiscoverVersions(proto.DiscoverVersionsRequest{})
	s.Require().EqualError(errors.Cause(err), "panic: oops!")
	s.Require().Equal(errors.Cause(err).(Error).ResultReason(), ttlv.RESULT_REASON_GENERAL_FAILURE)
}

func (s *ServerSuite) TestOperationFailWithReason() {
	s.server.Handle(ttlv.OPERATION_DISCOVER_VERSIONS, func(req *RequestContext, item *proto.RequestBatchItem) (interface{}, error) {
		return nil, WrapError(errors.New("oops!"), ttlv.RESULT_REASON_CRYPTOGRAPHIC_FAILURE)
	})

	s.Require().NoError(s.client.Connect())

	_, err := s.client.DiscoverVersions(proto.DiscoverVersionsRequest{})
	s.Require().EqualError(errors.Cause(err), "oops!")
	s.Require().Equal(errors.Cause(err).(Error).ResultReason(), ttlv.RESULT_REASON_CRYPTOGRAPHIC_FAILURE)
}

func (s *ServerSuite) TestOperationNotSupported() {
	s.Require().NoError(s.client.Connect())

	_, err := s.client.Send(ttlv.OPERATION_GET, proto.GetRequest{})
	s.Require().EqualError(errors.Cause(err), "operation not supported")
	s.Require().Equal(errors.Cause(err).(Error).ResultReason(), ttlv.RESULT_REASON_OPERATION_NOT_SUPPORTED)
}

func TestServerSuite(t *testing.T) {
	suite.Run(t, new(ServerSuite))
}
