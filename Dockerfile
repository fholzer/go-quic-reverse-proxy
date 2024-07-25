FROM golang:1.22.4-alpine

WORKDIR /usr/app

ADD . /usr/app

RUN --mount=type=cache,target=/root/.cache/go-build \
    go build .


FROM alpine

COPY --from=0 /usr/app/go-quic-reverse-proxy /usr/bin/go-quic-reverse-proxy

RUN chmod +x /usr/bin/go-quic-reverse-proxy

WORKDIR /etc/quic

ENTRYPOINT ["/usr/bin/go-quic-reverse-proxy"]
CMD ["-v"]
