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
	Bbrv1                      bool
	Disable1rttEncryption      bool
	Interval                   time.Duration
}

func RunClient(cliConf *ClientConfig) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	quicConf := config.Clone()
	if cliConf.Bbrv1 {
		log.Println("Feature bbrv1: ON")
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
	defer conn.CloseWithError(0, "")
	str, err := conn.OpenStream()
	if err != nil {
		return err
	}
	uploadTook, downloadTook, err := handleClientStream(str, cliConf.UploadBytes, cliConf.DownloadBytes, cliConf.Interval)
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

func handleClientStream(str io.ReadWriteCloser, uploadBytes, downloadBytes uint64, interval time.Duration) (uploadTook, downloadTook time.Duration, err error) {
	uploadRemaining := uploadBytes
	downloadRemaining := downloadBytes
	if interval > 0 {
		start := time.Now()
		ticker := time.NewTicker(interval)
		go func() {
			for t := range ticker.C {
				log.Printf("Time elapsed: %.2fs, upload: %d%%, download: %d%%",
					t.Sub(start).Seconds(),
					100-uploadRemaining*100/uploadBytes,
					100-downloadRemaining*100/downloadBytes)
			}
		}()
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, downloadBytes)
	if _, err := str.Write(b); err != nil {
		return 0, 0, err
	}
	// upload data
	log.Println("Upload data start.")
	b = make([]byte, 16*1024)
	uploadStart := time.Now()
	for uploadRemaining > 0 {
		if uploadRemaining < uint64(len(b)) {
			b = b[:uploadRemaining]
		}
		n, err := str.Write(b)
		if err != nil {
			return 0, 0, err
		}
		uploadRemaining -= uint64(n)
	}
	if err := str.Close(); err != nil {
		return 0, 0, err
	}
	uploadTook = time.Since(uploadStart)
	log.Println("Upload data complete.")
	// download data
	log.Println("Download data start.")
	b = b[:cap(b)]
	downloadStart := time.Now()
	for downloadRemaining > 0 {
		n, err := str.Read(b)
		if uint64(n) > downloadRemaining {
			return 0, 0, fmt.Errorf("server sent more data than expected, expected %d, got %d", downloadBytes, downloadRemaining+uint64(n))
		}
		downloadRemaining -= uint64(n)
		if err != nil {
			if err == io.EOF {
				if downloadRemaining == 0 {
					break
				}
				return 0, 0, fmt.Errorf("server didn't send enough data, expected %d, got %d", downloadBytes, downloadBytes-downloadRemaining)
			}
			return 0, 0, err
		}
	}
	log.Println("Download data complete.")
	return uploadTook, time.Since(downloadStart), nil
}
