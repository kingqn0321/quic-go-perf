package perf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/sirupsen/logrus"
)

type ServerConfig struct {
	Addr                  string
	KeyLogFile            io.Writer
	Bbrv1                 bool
	Disable1rttEncryption bool
}

func RunServer(srvConf *ServerConfig) error {
	tlsConf, err := generateSelfSignedTLSConfig()
	if err != nil {
		panic(err)
	}
	tlsConf.NextProtos = []string{ALPN}
	tlsConf.KeyLogWriter = srvConf.KeyLogFile
	os.Setenv("QLOGDIR", "./qlogs")
	quicConf := &quic.Config{
		Tracer: qlog.DefaultTracer,
	}

	if srvConf.Bbrv1 {
		logrus.Println("Feature bbrv1: ON")
		quicConf.CC = quic.CcBbr
	}

	if srvConf.Disable1rttEncryption {
		logrus.Println("Feature disable_1rtt_encryption: ON")
		quicConf.Disable1RTTEncryption = true
	}
	ln, err := quic.ListenAddr(srvConf.Addr, tlsConf, quicConf)
	if err != nil {
		return err
	}
	logrus.Println("Listening on", ln.Addr())
	defer ln.Close()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return fmt.Errorf("accept error: %w", err)
		}
		go func(conn quic.Connection) {
			if err := handleConn(conn); err != nil {
				logrus.Printf("handling conn from %s failed: %s\n", conn.RemoteAddr(), err)
			}
		}(conn)
	}
}

func handleConn(conn quic.Connection) error {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		go func(str quic.Stream) {
			if err := handleServerStream(str); err != nil {
				logrus.Printf("handling stream from %s failed: %s\n", conn.RemoteAddr(), err)
			}
		}(str)
	}
}

func handleServerStream(str io.ReadWriteCloser) error {
	b := make([]byte, 8)
	if _, err := io.ReadFull(str, b); err != nil {
		return err
	}
	amount := binary.BigEndian.Uint64(b)
	b = make([]byte, 16*1024)
	// receive data until the client sends a FIN
	for {
		if _, err := str.Read(b); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	// send as much data as the client requested
	for amount > 0 {
		if amount < uint64(len(b)) {
			b = b[:amount]
		}
		n, err := str.Write(b)
		if err != nil {
			return err
		}
		amount -= uint64(n)
	}
	return str.Close()
}

func generateSelfSignedTLSConfig() (*tls.Config, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	b, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
