FROM golang:1.20-alpine3.18

WORKDIR /usr/app

ADD . /usr/app

ENTRYPOINT ["/usr/app/go-quic-reverse-proxy"]
CMD ["-v"]

RUN --mount=type=cache,target=/root/.cache/go-build \
    go build .

RUN chmod o+x go-quic-reverse-proxy

WORKDIR /etc/quic