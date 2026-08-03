FROM golang:1.21-bookworm AS builder
RUN go install github.com/lc/gau/v2/cmd/gau@latest

FROM debian:bookworm-slim
COPY --from=builder /go/bin/gau /usr/local/bin/gau
ENTRYPOINT ["gau"]
