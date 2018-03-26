package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
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
	"github.com/lucas-clemente/quic-go/h2quic"
)

func loadConfig(file string) (*ConfigData, error) {
	r, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	res := ConfigData{}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

func main() {
	rpConfig, err := loadConfig("config.json")
	if err != nil {
		log.Println("Failed to load config file.")
		panic(err)
	}
	log.Println("Here's the config as loaded from file.")
	spew.Dump(rpConfig)

	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s backend_url\n", os.Args[0])
		return
	}

	var wg sync.WaitGroup
	for _, s := range rpConfig.Servers {
		wg.Add(len(s.Bindings))

		// prepare certificates
		certs := make([]tls.Certificate, 1)
		for i, c := range s.Certificates {
			certs[i], err = tls.LoadX509KeyPair(c.Fullchain, c.Privkey)
			if err != nil {
				panic(err)
			}
		}

		tlsConfig := tls.Config{
			Certificates: certs,
		}

		// build name/certificate map
		tlsConfig.BuildNameToCertificate()

		// check whether all mentioned vhost hostnames actually have a corresponding certificate
		for _, v := range s.VirtualServers {
			if !hasCertificate(tlsConfig, v.Hostname) {
				panic(errors.New("No certificate found for hostname '" + v.Hostname + "'"))
			}
		}

		handler := buildProxyHandler(s)

		for _, addr := range s.Bindings {
			pl, err := listenPacket(addr)
			if err != nil {
				panic(err)
			}

			go func() {
				var err error
				server := h2quic.Server{
					Server: &http.Server{
						Addr:      addr,
						Handler:   handler,
						TLSConfig: &tlsConfig,
					},
				}
				err = server.Serve(pl)

				if err != nil {
					fmt.Println(err)
				}
				wg.Done()
			}()
		}
	}
	wg.Wait()
}

func listenPacket(addr string) (net.PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", udpAddr)
}

// modified verions of crypto/tls/common.go getCertificate
func hasCertificate(c tls.Config, serverName string) bool {
	if c.GetCertificate != nil {
		panic(errors.New("'GetCertificate' not supported when checking for presence of certificates."))
	}
	if c.NameToCertificate == nil {
		panic(errors.New("Need 'NameToCertificate' map when checking for presence of certificates."))
	}

	if len(c.Certificates) == 0 {
		return false
	}

	name := strings.ToLower(serverName)
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	if _, ok := c.NameToCertificate[name]; ok {
		return true
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if _, ok := c.NameToCertificate[candidate]; ok {
			return true
		}
	}

	return false
}

func buildProxyHandler(s Server) http.Handler {
	exactMatch := map[string]http.Handler{}

	for _, v := range s.VirtualServers {
		// normalize hostname
		hn := strings.ToLower(v.Hostname)
		// build proxy
		parsedUrl, err := url.Parse(v.Upstream)
		if err != nil {
			log.Fatal("Failed to parse upstream URL")
			panic(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(parsedUrl)

		// build maps for easy lookup
		if strings.Contains(hn, "*") {
			panic(errors.New("Wildcard hosts aren'T supported yet!"))
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
