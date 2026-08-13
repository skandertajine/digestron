# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    go mod download
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=none
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags="-s -w \
        -X github.com/skandertajine/digestron/internal/version.Version=$VERSION \
        -X github.com/skandertajine/digestron/internal/version.Commit=$COMMIT" \
      -o /out/digestron ./cmd/digestron

# distroless/static ships CA certs, tzdata and a nonroot user — everything a
# static Go binary needs and nothing else.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/digestron /usr/local/bin/digestron
USER 65532:65532
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/digestron"]
CMD ["serve", "-config", "/etc/digestron/config.yaml"]
