FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git make gcc musl-dev
RUN git clone https://github.com/assetnote/kiterunner.git /kiterunner
WORKDIR /kiterunner
RUN make build

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /kiterunner/dist/kr /usr/local/bin/kb
RUN mkdir -p /wordlists && \
    echo '[{"path":"/api/v1/users","method":"GET"},{"path":"/api/v2/items","method":"POST"},{"path":"/api/config","method":"GET"}]' > /wordlists/routes.json && \
    /usr/local/bin/kb kb compile /wordlists/routes.json /wordlists/routes.kite
ENTRYPOINT []
