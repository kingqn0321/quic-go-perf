package main

import (
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/quic-go/perf"
)

type Options struct {
	RunServer             bool   `long:"run-server" description:"run as server, default: false"`
	KeyLogFile            string `long:"key-log" description:"export TLS keys"`
	ServerAddress         string `long:"server-address" description:"server address, required"`
	Interval              string `long:"interval" description:"check interval (second), default: 10"`
	UploadBytes           string `long:"upload-bytes" description:"upload bytes #[KMG]"`
	DownloadBytes         string `long:"download-bytes" description:"download bytes #[KMG]"`
	Bbrv1                 bool   `long:"bbrv1" description:"bbrv1, default: false"`
	Disable1rttEncryption bool   `long:"d1e" description:"disable 1rtt encryption, default: false"`
}

func main() {
	var opt Options
	parser := flags.NewParser(&opt, flags.IgnoreUnknown)
	_, err := parser.Parse()
	if err != nil {
		panic(err)
	}

	if opt.ServerAddress == "" {
		parser.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	var keyLogFile io.Writer
	if opt.KeyLogFile != "" {
		f, err := os.Create(opt.KeyLogFile)
		if err != nil {
			log.Fatalf("failed to create key log file: %s", err)
		}
		defer f.Close()
		keyLogFile = f
	}

	if opt.Interval == "" {
		opt.Interval = "10"
	}

	if opt.RunServer {
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
		}()
		if err := perf.RunServer(&perf.ServerConfig{
			Addr:                  opt.ServerAddress,
			KeyLogFile:            keyLogFile,
			Bbrv1:                 opt.Bbrv1,
			Disable1rttEncryption: opt.Disable1rttEncryption,
		}); err != nil {
			log.Fatal(err)
		}
	} else {
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:6061", nil))
		}()
		if err := perf.RunClient(&perf.ClientConfig{
			Addr:                  opt.ServerAddress,
			UploadBytes:           perf.ParseBytes(opt.UploadBytes),
			DownloadBytes:         perf.ParseBytes(opt.DownloadBytes),
			KeyLogFile:            keyLogFile,
			Bbrv1:                 opt.Bbrv1,
			Disable1rttEncryption: opt.Disable1rttEncryption,
			Interval:              time.Duration(perf.ParseNumber(opt.Interval) * int64(time.Second)),
		}); err != nil {
			log.Fatal(err)
		}
	}
}
