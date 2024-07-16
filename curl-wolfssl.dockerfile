FROM alpine AS builder

RUN apk add git alpine-sdk autoconf automake libtool


FROM builder AS wolfssl
WORKDIR /usr/app
RUN git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
WORKDIR /usr/app/wolfssl
RUN autoreconf -fi
RUN ./configure --prefix=/usr/prefix/wolfssl --enable-quic --enable-session-ticket --enable-earlydata --enable-psk --enable-harden --enable-altcertchains
RUN make -j$(nproc)
RUN make install


FROM builder AS nghttp3
WORKDIR /usr/app
RUN git clone -b v1.1.0 --depth 1 https://github.com/ngtcp2/nghttp3
WORKDIR /usr/app/nghttp3
RUN git submodule update --init
RUN autoreconf -fi
RUN ./configure --prefix=/usr/prefix/nghttp3 --enable-lib-only
RUN make -j$(nproc)
RUN make install


FROM builder AS ngtcp2
COPY --from=wolfssl /usr/prefix/wolfssl /usr/prefix/wolfssl
COPY --from=nghttp3 /usr/prefix/nghttp3 /usr/prefix/nghttp3
WORKDIR /usr/app
RUN git clone -b v1.2.0 --depth 1 https://github.com/ngtcp2/ngtcp2
WORKDIR /usr/app/ngtcp2
RUN autoreconf -fi
RUN ./configure PKG_CONFIG_PATH=/usr/prefix/wolfssl/lib/pkgconfig:/usr/prefix/nghttp3/lib/pkgconfig LDFLAGS="-Wl,-rpath,/usr/prefix/openssl/lib64" --prefix=/usr/prefix/ngtcp2 --with-wolfssl --enable-lib-only
RUN make -j$(nproc)
RUN make install
ENTRYPOINT ["/bin/sh"]


FROM builder AS curl
COPY --from=wolfssl /usr/prefix/wolfssl /usr/prefix/wolfssl
COPY --from=nghttp3 /usr/prefix/nghttp3 /usr/prefix/nghttp3
COPY --from=ngtcp2 /usr/prefix/ngtcp2 /usr/prefix/ngtcp2
WORKDIR /usr/app
RUN git clone --depth 1 https://github.com/curl/curl
WORKDIR /usr/app/curl
RUN autoreconf -fi
RUN ./configure PKG_CONFIG_PATH=/usr/prefix/wolfssl/lib/pkgconfig:/usr/prefix/nghttp3/lib/pkgconfig LDFLAGS="-Wl,-rpath,/usr/prefix/wolfssl/lib" --with-wolfssl=/usr/prefix/wolfssl --with-nghttp3=/usr/prefix/nghttp3 --with-ngtcp2=/usr/prefix/ngtcp2
RUN make -j$(nproc)
RUN make install


FROM alpine

COPY --from=wolfssl /usr/prefix/wolfssl /usr/prefix/wolfssl
COPY --from=nghttp3 /usr/prefix/nghttp3 /usr/prefix/nghttp3
COPY --from=ngtcp2 /usr/prefix/ngtcp2 /usr/prefix/ngtcp2
COPY --from=curl /usr/local /usr/local

ENTRYPOINT ["/usr/local/bin/curl"]