package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

type CertificateWithChains struct {
	Certificate tls.Certificate
	ChainPool   *x509.CertPool
	Chain       []*x509.Certificate
}

func NewCertificateWithChains(certFile, keyFile string) (*CertificateWithChains, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatalf("Failed to parse certificate %s", certFile)
	}
	cert.Leaf = leaf

	chainPool := x509.NewCertPool()
	chainCerts := make([]*x509.Certificate, 0, len(cert.Certificate))
	for i := 0; i < len(cert.Certificate); i++ {
		chainCert, err := x509.ParseCertificate(cert.Certificate[i])
		if err != nil {
			log.Fatalf("Failed to parse certificate #%d in %s", i+1, certFile)
		}

		if chainCert.IsCA {
			log.Debugf("Cert for '%s' is a CA certificate", chainCert.Subject)
			chainPool.AddCert(chainCert)
			chainCerts = append(chainCerts, chainCert)
		}
	}
	log.Debugf("Parsed certificate valid for >>%s<<, with %d chain certificates", strings.Join(leaf.DNSNames, ", "), len(chainCerts))

	return &CertificateWithChains{
		Certificate: cert,
		ChainPool:   chainPool,
		Chain:       chainCerts,
	}, nil
}

func hasCertificate(c []*CertificateWithChains, serverName string) bool {
	log.Debugf("Looking for certificate for %s", serverName)

	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal("Failed to load system CA certificate pool")
	}

	for _, cert := range c {
		opts := x509.VerifyOptions{
			DNSName: serverName,
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			Intermediates: cert.ChainPool,
			Roots:         systemCertPool.Clone(),
		}

		// in order to support non-publicly signed certs, let's assume user provided
		// certificate chain contains trustworthy CA certificates
		for _, intermeditateCert := range cert.Chain {
			opts.Roots.AddCert(intermeditateCert)
		}

		if _, err := cert.Certificate.Leaf.Verify(opts); err == nil {
			return true
		}
	}

	return false
}

func NewPoolFromPem(filename string) (*x509.CertPool, error) {
	clientCaData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("CA file couldn't be read: %w", err)
	}

	clientCaPool := x509.NewCertPool()
	ok := clientCaPool.AppendCertsFromPEM(clientCaData)
	if !ok {
		return nil, fmt.Errorf("no certificates found in CA file")
	}

	return clientCaPool, nil
}
