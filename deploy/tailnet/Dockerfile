FROM golang:1.26-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -buildvcs=false -trimpath -o /cli-proxy-api ./cmd/server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 cliproxy && useradd --uid 10001 --gid 10001 --home-dir /data cliproxy
COPY --from=build /cli-proxy-api /usr/local/bin/cli-proxy-api
# Build the matching frontend fork and copy its dist/index.html here before building.
COPY deploy/tailnet/static/management.html /opt/cliproxyapi/static/management.html
ENV MANAGEMENT_STATIC_PATH=/opt/cliproxyapi/static
WORKDIR /data
USER 10001:10001
EXPOSE 8317
ENTRYPOINT ["/usr/local/bin/cli-proxy-api"]
CMD ["--config", "/data/config.yaml", "--local-model"]
