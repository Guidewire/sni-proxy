package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gorilla/handlers"
	"gopkg.in/natefinch/lumberjack.v2"
	yaml "gopkg.in/yaml.v2"
)

var config_path = flag.String("c", "config.yaml", "Path to a config file")
var cfg = Config{}

type Config struct {
	CrtFilePath   string        `yaml:"certificate_crt_path"`
	KeyFilePath   string        `yaml:"certificate_key_path"`
	ListenHttps   string        `yaml:"listen_https_address"`
	AccessLog     string        `yaml:"access_log"`
	ErrorLog      string        `yaml:"error_log"`
	LogMaxSizeMB  int           `yaml:"log_max_size_mb"`
	LogMaxBackups int           `yaml:"log_max_backups"`
	LogMaxAgeDays int           `yaml:"log_max_age_days"`
	PidFile       string        `yaml:"pid_file"`
	Proxies       []ProxyConfig `yaml:"proxies"`
}

type ProxyConfig struct {
	Hostname    string `yaml:"hostname"`
	Target      string `yaml:"target"`
	Location    string `yaml:"location"`
	KeyFilePath string `yaml:"certificate_key_path"`
	CrtFilePath string `yaml:"certificate_crt_path"`
}

type HostMap map[string]*ProxyConfig

var hostMap HostMap

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func headerByName(req *http.Request, header string) string {
	if values, ok := req.Header[header]; ok && len(values) > 0 {
		return values[0]
	} else {
		return "-"
	}
}

func newSingleHostReverseProxyWithHeaders(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	return &httputil.ReverseProxy{Director: director}
}

func reverseProxy(w http.ResponseWriter, request *http.Request) {
	var target string
	// log.Printf("Request host: %s", request.Host)
	if proxy, ok := hostMap[request.Host]; ok {
		// log.Printf("Detected: %s, proxy to %s", request.Host, proxy.Target)
		target = proxy.Target
	} else if proxy, ok := hostMap["*"]; ok {
		// log.Printf("Detected: *, proxy to %s", proxy.Target)
		target = proxy.Target
	} else {
		log.Printf("Unknown host %s", request.Host)
	}
	url, err := url.Parse(target)
	if err != nil {
		log.Printf("Proxy error: %#v", err)
	}
	proxy := newSingleHostReverseProxyWithHeaders(url)
	proxy.ServeHTTP(w, request)
}

func removePid() {
	err := os.Remove(cfg.PidFile)
	if err != nil {
		log.Printf("ERROR: Can't remove pid file %s: %v", cfg.PidFile, err)
	} else {
		log.Printf("Removed pid file")
	}
}

func addCert(tlsConf *tls.Config, crt, key string) {
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		log.Fatal(err)
	}
	tlsConf.Certificates = append(tlsConf.Certificates, cert)
}

func main() {
	flag.Parse()

	log.Printf("Reading config file...")
	content, err := ioutil.ReadFile(*config_path)
	if err != nil {
		log.Fatalf("Problem reading configuration file: %v", err)
	}

	log.Printf("Parsing config file...")
	err = yaml.Unmarshal(content, &cfg)
	if err != nil {
		log.Fatalf("Error parsing configuration file: %v", err)
	}

	hostMap = make(HostMap, len(cfg.Proxies))

	tlsConf := &tls.Config{}

	if cfg.CrtFilePath != "" && cfg.KeyFilePath != "" {
		addCert(tlsConf, cfg.CrtFilePath, cfg.KeyFilePath)
	}

	for _, proxy := range cfg.Proxies {
		if proxy.CrtFilePath != "" && proxy.KeyFilePath != "" {
			addCert(tlsConf, proxy.CrtFilePath, proxy.KeyFilePath)
		}
		p := proxy
		hostMap[proxy.Hostname] = &p
	}

	tlsConf.BuildNameToCertificate()

	log.Printf("Configuring logs...")

	errLogger := &lumberjack.Logger{
		Filename:   cfg.ErrorLog,
		MaxSize:    cfg.LogMaxSizeMB,
		MaxBackups: cfg.LogMaxBackups,
		MaxAge:     cfg.LogMaxAgeDays,
	}

	accessLogger := &lumberjack.Logger{
		Filename:   cfg.ErrorLog,
		MaxSize:    cfg.LogMaxSizeMB,
		MaxBackups: cfg.LogMaxBackups,
		MaxAge:     cfg.LogMaxAgeDays,
	}

	server := http.Server{
		Addr: cfg.ListenHttps,
		Handler: handlers.LoggingHandler(
			accessLogger, http.HandlerFunc(
				reverseProxy,
			),
		),
		// waiting for https://github.com/NYTimes/gziphandler/issues/40#issuecomment-325179025
		// Handler: gziphandler.GzipHandler(
		// 	handlers.LoggingHandler(
		// 		logFile, http.HandlerFunc(
		// 			reverseProxy,
		// 		),
		// 	),
		// ),
		TLSConfig: tlsConf,
	}

	if cfg.PidFile != "" {
		pid := os.Getpid()
		pidBytes := []byte(fmt.Sprintf("%d\n", pid))
		if _, err := os.Stat(cfg.PidFile); !os.IsNotExist(err) {
			log.Printf("ERROR: Pid file %s alredy exists, everwriting. %v", cfg.PidFile, err)
		}
		err = ioutil.WriteFile(cfg.PidFile, pidBytes, 0644)
		if err != nil {
			log.Printf("ERROR: Can't write pid to pid file %s: %v", cfg.PidFile, err)
		}
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			removePid()
			os.Exit(0)
		}()
		defer removePid()
	}
	log.Printf("Starting...")

	log.SetOutput(errLogger)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)

	go func() {
		for {
			<-c
			errLogger.Rotate()
		}
	}()
	log.Fatal(server.ListenAndServeTLS("", ""))
}
