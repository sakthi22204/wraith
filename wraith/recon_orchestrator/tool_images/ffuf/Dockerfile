# Stage 1: Build FFUF from source using bookworm (comes with git, gcc, musl-dev pre-installed)
FROM golang:1.21-bookworm AS builder

# Pin to a release tag. Cloning master pulled in a go.mod requiring go 1.26.0,
# which this builder cannot satisfy: the official golang images set
# GOTOOLCHAIN=local, so Go refuses to auto-download a newer toolchain and the
# build dies with "go.mod requires go >= 1.26.0 (running go 1.21.13)".
# v2.3.0 declares go 1.20, so it builds here -- and pinning means the next
# upstream go bump cannot break this image again.
ARG FFUF_VERSION=v2.3.0
RUN git clone --depth 1 --branch ${FFUF_VERSION} https://github.com/ffuf/ffuf.git /ffuf

WORKDIR /ffuf

# Build optimized static binary
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o ffuf .

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

# Copy pre-compiled binary
COPY --from=builder /ffuf/ffuf /usr/local/bin/ffuf

# Copy curated wordlist
COPY common.txt /wordlists/common.txt

ENTRYPOINT ["ffuf"]
