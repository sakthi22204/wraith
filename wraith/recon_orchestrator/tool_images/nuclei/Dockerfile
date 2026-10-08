# nuclei with its templates baked in at build time.
#
# Two reasons this is built here rather than pulled from upstream:
#
# 1. The stock projectdiscovery/nuclei image ships the binary but no templates. A
#    container created from it runs `nuclei -u ...`, finds zero templates, and
#    exits clean having tested nothing -- a silent no-op that reads as a passing
#    scan. Verified directly: `find / -name '*.yaml' -path '*nuclei-templates*'`
#    returns 0 entries in the stock image, 13,243 after `nuclei -ut`.
#
# 2. `nuclei -ut` fetches templates at RUNTIME, which needs egress from inside
#    the broker-spawned container and spends the tool's whole budget on the fetch
#    before scanning anything. Baking them in removes both failure modes.
#
# The binary comes from the upstream release tarball rather than `go build`.
# nuclei v3.11 declares `go 1.26` in its go.mod, and the official golang images
# set GOTOOLCHAIN=local, so building from source needs a builder that does not
# exist here yet -- the same class of failure the ffuf image already hit once.
# The release artifact is also what upstream publishes as the supported build.
FROM debian:bookworm-slim

ARG NUCLEI_VERSION=v3.11.1
ARG NUCLEI_TEMPLATES_REF=v10.5.0
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) arch=amd64 ;; \
        arm64) arch=arm64 ;; \
        *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    ver="${NUCLEI_VERSION#v}"; \
    curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${ver}_linux_${arch}.zip"; \
    unzip -o -q /tmp/nuclei.zip nuclei -d /tmp; \
    install -m 0755 /tmp/nuclei /usr/local/bin/nuclei; \
    rm -rf /tmp/nuclei /tmp/nuclei.zip

# Installed where nuclei's own lookup expects them, so no -ut is needed at run time.
RUN git clone --depth 1 --branch ${NUCLEI_TEMPLATES_REF} \
        https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates \
    && rm -rf /root/nuclei-templates/.git

ENTRYPOINT ["nuclei"]
