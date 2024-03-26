package perf

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

type Result struct {
	Latency float64 `json:"latency"`
}

type ClientConfig struct {
	Addr                       string
	UploadBytes, DownloadBytes uint64
	KeyLogFile                 io.Writer
	UseBbr                     bool
	Disable1rttEncryption      bool
}

func RunClient(cliConf *ClientConfig) error {
	start := time.Now()
	ticker := time.NewTicker(time.Second * 10)
	go func() {
		for t := range ticker.C {
			log.Printf("Time elapsed: %.2fs", t.Sub(start).Seconds())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	quicConf := config.Clone()
	if cliConf.UseBbr {
		log.Println("Feature use_bbr: ON")
		quicConf.CC = quic.CcBbr
	}
	if cliConf.Disable1rttEncryption {
		log.Println("Feature disable_1rtt_encryption: ON")
		quicConf.Disable1RTTEncryption = true
	}
	conn, err := quic.DialAddr(
		ctx,
		cliConf.Addr,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{ALPN},
			KeyLogWriter:       cliConf.KeyLogFile,
		},
		quicConf,
	)
	if err != nil {
		return err
	}
	str, err := conn.OpenStream()
	if err != nil {
		return err
	}
	uploadTook, downloadTook, err := handleClientStream(str, cliConf.UploadBytes, cliConf.DownloadBytes)
	if err != nil {
		return err
	}
	log.Printf("uploaded %s: %.2fs (%s/s)", formatBytes(cliConf.UploadBytes), uploadTook.Seconds(), formatBytes(bandwidth(cliConf.UploadBytes, uploadTook)))
	log.Printf("downloaded %s: %.2fs (%s/s)", formatBytes(cliConf.DownloadBytes), downloadTook.Seconds(), formatBytes(bandwidth(cliConf.DownloadBytes, downloadTook)))
	json, err := json.Marshal(Result{
		Latency: time.Since(start).Seconds(),
	})
	if err != nil {
		return err
	}
	fmt.Println(string(json))
	return nil
}

func handleClientStream(str io.ReadWriteCloser, uploadBytes, downloadBytes uint64) (uploadTook, downloadTook time.Duration, err error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, downloadBytes)
	if _, err := str.Write(b); err != nil {
		return 0, 0, err
	}
	// upload data
	log.Println("Upload data start.")
	b = make([]byte, 16*1024)
	uploadStart := time.Now()
	for uploadBytes > 0 {
		if uploadBytes < uint64(len(b)) {
			b = b[:uploadBytes]
		}
		n, err := str.Write(b)
		if err != nil {
			return 0, 0, err
		}
		uploadBytes -= uint64(n)
	}
	if err := str.Close(); err != nil {
		return 0, 0, err
	}
	uploadTook = time.Since(uploadStart)
	log.Println("Upload data complete.")
	// download data
	log.Println("Download data start.")
	b = b[:cap(b)]
	remaining := downloadBytes
	downloadStart := time.Now()
	for remaining > 0 {
		n, err := str.Read(b)
		if uint64(n) > remaining {
			return 0, 0, fmt.Errorf("server sent more data than expected, expected %d, got %d", downloadBytes, remaining+uint64(n))
		}
		remaining -= uint64(n)
		if err != nil {
			if err == io.EOF {
				if remaining == 0 {
					break
				}
				return 0, 0, fmt.Errorf("server didn't send enough data, expected %d, got %d", downloadBytes, downloadBytes-remaining)
			}
			return 0, 0, err
		}
	}
	log.Println("Download data complete.")
	return uploadTook, time.Since(downloadStart), nil
}
