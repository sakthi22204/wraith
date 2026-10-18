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
# The binary is copied out of the official upstream image rather than downloaded
# from the GitHub release zip. The release asset is served from a separate CDN
# (release-assets.githubusercontent.com) that is reachable from some networks
# and not others; the git-clone tool images still build while this one fails,
# which is exactly the signature of that CDN being blocked. Docker Hub is the
# transport we already depend on for every base image, so copying the binary
# from it is the reliable path. The copied file is the same binary upstream
# publishes as its supported build (statically linked, so it runs on bookworm).
#
# nuclei v3.11 declares `go 1.26` in its go.mod, and the official golang images
# set GOTOOLCHAIN=local, so building from source needs a builder that does not
# exist here yet -- the same class of failure the ffuf image already hit once.
ARG NUCLEI_VERSION=v3.11.1
FROM projectdiscovery/nuclei:${NUCLEI_VERSION} AS nuclei_bin

FROM debian:bookworm-slim

ARG NUCLEI_TEMPLATES_REF=v10.5.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nuclei_bin /usr/local/bin/nuclei /usr/local/bin/nuclei

# The templates git clone hits github.com and can fail transiently when the recon
# phase builds many tool images concurrently; retry before failing the build.
RUN for i in 1 2 3; do \
        git clone --depth 1 --branch ${NUCLEI_TEMPLATES_REF} \
            https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates \
            && rm -rf /root/nuclei-templates/.git && break || \
        { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done

ENTRYPOINT ["nuclei"]
