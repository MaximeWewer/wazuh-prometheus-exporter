# ---- build stage ----
# Runs on the native builder arch ($BUILDPLATFORM) and cross-compiles the static
# binary to the target arch — no QEMU emulation of the Go build (CGO is off).
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build \
      -ldflags="-w -s -extldflags '-static' -X main.Version=${VERSION}" \
      -trimpath -tags netgo \
      -o /out/wazuh-exporter ./cmd/wazuh-exporter

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/wazuh-exporter /wazuh-exporter
EXPOSE 9555
USER 65532:65532
ENTRYPOINT ["/wazuh-exporter"]
