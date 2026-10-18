FROM golang:1.21-bookworm AS builder
# `go install @latest` fetches modules over the network and can fail transiently
# when the recon phase builds many tool images concurrently; retry before
# failing the build.
RUN for i in 1 2 3; do \
      go install github.com/tomnomnom/waybackurls@latest && break || \
      { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done

FROM debian:bookworm-slim
COPY --from=builder /go/bin/waybackurls /usr/local/bin/waybackurls
ENTRYPOINT ["waybackurls"]
