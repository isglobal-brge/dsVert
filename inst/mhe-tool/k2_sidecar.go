//go:build ignore

package main

// k2_sidecar.go: DEPRECATED — Direct TCP/TLS sidecar abandoned in favour of
// client-relayed GS-IRLS (pragmatic mode) and HE-Link (strict mode).
// The two participating servers communicate directly without client relay.
// This eliminates the ~500ms/round DataSHIELD RPC overhead.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// SidecarConn wraps a TCP connection with framed message I/O.
type SidecarConn struct {
	conn net.Conn
}

// Send sends a length-prefixed message.
func (sc *SidecarConn) Send(data []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := sc.conn.Write(header); err != nil {
		return fmt.Errorf("send header: %w", err)
	}
	if _, err := sc.conn.Write(data); err != nil {
		return fmt.Errorf("send body: %w", err)
	}
	return nil
}

// Recv receives a length-prefixed message.
func (sc *SidecarConn) Recv() ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(sc.conn, header); err != nil {
		return nil, fmt.Errorf("recv header: %w", err)
	}
	length := binary.BigEndian.Uint32(header)
	data := make([]byte, length)
	if _, err := io.ReadFull(sc.conn, data); err != nil {
		return nil, fmt.Errorf("recv body: %w", err)
	}
	return data, nil
}

func (sc *SidecarConn) Close() error {
	return sc.conn.Close()
}

// StartServer listens for one incoming connection on the given port.
func StartServer(port int, tlsCert, tlsKey, tlsCA string) (*SidecarConn, error) {
	var listener net.Listener
	var err error

	if tlsCert != "" && tlsKey != "" {
		// TLS mode
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			return nil, fmt.Errorf("load TLS cert: %w", err)
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		if tlsCA != "" {
			caCert, err := os.ReadFile(tlsCA)
			if err != nil {
				return nil, fmt.Errorf("load CA cert: %w", err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caCert)
			config.ClientCAs = pool
		}
		listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", port), config)
	} else {
		// Plain TCP (for testing)
		listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	}
	if err != nil {
		return nil, fmt.Errorf("listen on port %d: %w", port, err)
	}
	defer listener.Close()

	listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Minute))
	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}
	return &SidecarConn{conn: conn}, nil
}

// ConnectToPeer connects to the peer server.
func ConnectToPeer(host string, port int, tlsCert, tlsKey, tlsCA string) (*SidecarConn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	var conn net.Conn
	var err error

	if tlsCert != "" && tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			return nil, fmt.Errorf("load TLS cert: %w", err)
		}
		config := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true, // TODO: verify peer cert properly
		}
		if tlsCA != "" {
			caCert, err := os.ReadFile(tlsCA)
			if err != nil {
				return nil, fmt.Errorf("load CA cert: %w", err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caCert)
			config.RootCAs = pool
			config.InsecureSkipVerify = false
		}
		conn, err = tls.Dial("tcp", addr, config)
	} else {
		// Retry connection (peer might not be listening yet)
		for attempt := 0; attempt < 30; attempt++ {
			conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
			if err == nil {
				break
			}
			time.Sleep(time.Second)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	return &SidecarConn{conn: conn}, nil
}
