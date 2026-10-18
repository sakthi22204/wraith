# Stage 1: Build Kiterunner from source using bookworm (comes with git, make, gcc, curl, tar pre-installed)
FROM golang:1.21-bookworm AS builder

# Clone official Kiterunner repository. git clone and the wordlist curl below
# can fail transiently when the recon phase builds many tool images
# concurrently; retry each before failing the build.
RUN for i in 1 2 3; do \
      git clone https://github.com/assetnote/kiterunner.git /kiterunner && break || \
      { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done

WORKDIR /kiterunner

# Build Kiterunner
RUN make build

# Download and extract the routes wordlist in the builder stage
RUN for i in 1 2 3; do \
      mkdir -p /wordlists && \
      curl -sSfL -o /wordlists/routes-small.kite.tar.gz https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz && \
      tar -xzf /wordlists/routes-small.kite.tar.gz -C /wordlists && \
      rm /wordlists/routes-small.kite.tar.gz && break || \
      { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

# Copy pre-compiled binary
COPY --from=builder /kiterunner/dist/kr /usr/local/bin/kb

# Copy pre-downloaded wordlist
COPY --from=builder /wordlists/routes-small.kite /wordlists/routes-small.kite

CMD ["kb"]
