package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	_ "net/http/pprof"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/handlers"
	"github.com/quic-go/quic-go/http3"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func loadConfig(file string) (*ConfigData, error) {
	r, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	res := &ConfigData{}
	dec := yaml.NewDecoder(r)
	if err := dec.Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}

func main() {
	var verbose bool
	flag.BoolVar(&verbose, "v", false, "Enable debug logging.")
	flag.Parse()

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	rpConfig, err := loadConfig("config.yml")
	if err != nil {
		log.Fatalf("Failed to load config file: %s", err.Error())
	}
	log.Debug("Here's the config as loaded from file.")
	log.Debug(spew.Sdump(rpConfig))

	var wg sync.WaitGroup
	for _, s := range rpConfig.Servers {
		wg.Add(len(s.Bindings))

		// prepare certificates
		allCerts := make([]tls.Certificate, 0, 32)
		certs := make([]*CertificateWithChains, len(s.Certificates))
		for i, c := range s.Certificates {
			certs[i], err = NewCertificateWithChains(c.Fullchain, c.Privkey)
			if err != nil {
				log.Fatalf("Error processing certificates: %s", err.Error())
			}
			allCerts = append(allCerts, certs[i].Certificate)
		}

		// check whether all mentioned vhost hostnames actually have a corresponding certificate
		for _, v := range s.VirtualServers {
			if !hasCertificate(certs, v.Hostname) {
				panic(errors.New("No certificate found for hostname '" + v.Hostname + "'"))
			}
		}

		tlsConfig := tls.Config{
			Certificates: allCerts,
		}

		handler := buildProxyHandler(s)

		for _, addr := range s.Bindings {
			pl, err := listenPacket(addr)
			if err != nil {
				panic(err)
			}
			defer pl.Close()

			go func() {
				var err error
				server := &http3.Server{
					Handler:   handler,
					TLSConfig: &tlsConfig,
				}
				err = server.Serve(pl)

				if err != nil {
					fmt.Println(err)
				}
				wg.Done()
			}()
		}
	}
	log.Info("Server started")
	wg.Wait()
	log.Info("Server stopped")
}

func listenPacket(addr string) (net.PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", udpAddr)
}

func buildProxyHandler(s Server) http.Handler {
	exactMatch := map[string]http.Handler{}

	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
	}
	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	for _, v := range s.VirtualServers {
		// normalize hostname
		hn := strings.ToLower(v.Hostname)
		// build proxy
		parsedUrl, err := url.Parse(v.Upstream)
		if err != nil {
			log.Fatalf("Failed to parse upstream URL: %s", err.Error())
		}
		proxy := httputil.NewSingleHostReverseProxy(parsedUrl)
		proxy.Transport = &transport

		// build maps for easy lookup
		if strings.Contains(hn, "*") {
			panic(errors.New("wildcard hosts aren't supported yet"))
		} else {
			exactMatch[hn] = proxy
		}
	}
	vhostHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hn := strings.ToLower(req.Host)
		if h, ok := exactMatch[hn]; ok {
			h.ServeHTTP(w, req)
			return
		} else {
			http.DefaultServeMux.ServeHTTP(w, req)
			return
		}
	})
	return handlers.CombinedLoggingHandler(os.Stdout, vhostHandler)
}
