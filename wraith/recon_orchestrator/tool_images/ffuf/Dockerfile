# Stage 1: Build FFUF from source using bookworm (comes with git, gcc, musl-dev pre-installed)
FROM golang:1.21-bookworm AS builder

# Clone official FFUF repository
RUN git clone https://github.com/ffuf/ffuf.git /ffuf

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
