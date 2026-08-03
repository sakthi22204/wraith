FROM golang:1.21-bookworm AS builder
RUN go install github.com/tomnomnom/waybackurls@latest

FROM debian:bookworm-slim
COPY --from=builder /go/bin/waybackurls /usr/local/bin/waybackurls
ENTRYPOINT ["waybackurls"]
