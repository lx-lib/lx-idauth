ARG BASE_IMAGE=ghcr.io/wntrtech/scratch:v1.0.0
FROM ${BASE_IMAGE}

EXPOSE 8080/tcp
COPY publish/ /

ENTRYPOINT ["/server", "web"]
HEALTHCHECK --start-period=30s --start-interval=5s --interval=1m --timeout=10s --retries=5 CMD ["/server", "health"]