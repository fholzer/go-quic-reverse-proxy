FROM alpine AS builder

RUN apk add git alpine-sdk autoconf automake libtool
WORKDIR /usr/app

RUN git clone --depth 1 https://github.com/wolfSSL/wolfssl.git && \
    cd wolfssl && \
    autoreconf -fi && \
    ./configure --enable-quic --enable-session-ticket --enable-earlydata --enable-psk --enable-harden --enable-altcertchains && \
    make && \
    make install


RUN git clone -b v1.1.0 --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && \
    git submodule update --init && \
    autoreconf -fi && \
    ./configure --enable-lib-only && \
    make && \
    make install


RUN git clone -b v1.2.0 --depth 1 https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && \
    autoreconf -fi && \
    ./configure PKG_CONFIG_PATH=/usr/local/lib/pkgconfig LDFLAGS="-Wl,-rpath,/usr/local/lib" --enable-lib-only --with-wolfssl && \
    make && \
    make install


RUN git clone --depth 1 https://github.com/curl/curl && \
    cd curl && \
    autoreconf -fi && \
    ./configure --with-wolfssl=/usr/local/lib --with-nghttp3 --with-ngtcp2 && \
    make && \
    make install


FROM alpine

COPY --from=0 /usr/local /usr/local

ENTRYPOINT ["/usr/local/bin/curl"]