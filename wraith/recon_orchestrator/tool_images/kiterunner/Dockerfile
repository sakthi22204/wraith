FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git make gcc musl-dev
RUN git clone https://github.com/assetnote/kiterunner.git /kiterunner
WORKDIR /kiterunner
RUN make build

FROM alpine:latest
RUN apk add --no-cache ca-certificates curl tar
COPY --from=builder /kiterunner/dist/kr /usr/local/bin/kb
RUN mkdir -p /wordlists && \
    curl -sSfL -o /wordlists/routes-small.kite.tar.gz https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz && \
    tar -xzf /wordlists/routes-small.kite.tar.gz -C /wordlists && \
    rm /wordlists/routes-small.kite.tar.gz
ENTRYPOINT []
