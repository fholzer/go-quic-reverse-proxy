package main

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/metrics"
)

func NewConnectionTracer(reg *prometheus.Registry) func(_ context.Context, p logging.Perspective, _ logging.ConnectionID) *logging.ConnectionTracer {
	return func(_ context.Context, p logging.Perspective, _ logging.ConnectionID) *logging.ConnectionTracer {
		switch p {
		case logging.PerspectiveClient:
			return metrics.NewClientConnectionTracerWithRegisterer(reg)
		case logging.PerspectiveServer:
			return metrics.NewServerConnectionTracerWithRegisterer(reg)
		default:
			panic("invalid perspective")
		}
	}
}
