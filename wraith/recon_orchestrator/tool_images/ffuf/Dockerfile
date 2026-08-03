# Stage 1: Build FFUF from source
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

# Clone official FFUF repository
RUN git clone https://github.com/ffuf/ffuf.git /ffuf

WORKDIR /ffuf

# Build optimized static binary
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o ffuf .

# Stage 2: Final minimal image
FROM alpine:latest

RUN apk add --no-cache ca-certificates

# Copy pre-compiled binary
COPY --from=builder /ffuf/ffuf /usr/local/bin/ffuf

# Copy curated wordlist
COPY common.txt /wordlists/common.txt

ENTRYPOINT ["ffuf"]
