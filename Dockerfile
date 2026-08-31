# syntax=docker/dockerfile:1

# Build stage. The TigerBeetle client links its prebuilt static library via
# CGO, so the toolchain needs gcc; the runtime images are distroless with
# glibc (base-debian12), running as non-root.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

# Per-command runtime targets (distroless, non-root).
FROM gcr.io/distroless/base-debian12:nonroot AS ferry-api
COPY --from=build /out/ferry-api /ferry-api
USER nonroot:nonroot
ENTRYPOINT ["/ferry-api"]

FROM gcr.io/distroless/base-debian12:nonroot AS ferry-worker
COPY --from=build /out/ferry-worker /ferry-worker
USER nonroot:nonroot
ENTRYPOINT ["/ferry-worker"]

FROM gcr.io/distroless/base-debian12:nonroot AS outbox-publisher
COPY --from=build /out/outbox-publisher /outbox-publisher
USER nonroot:nonroot
ENTRYPOINT ["/outbox-publisher"]

FROM gcr.io/distroless/base-debian12:nonroot AS metocean-bridge
COPY --from=build /out/metocean-bridge /metocean-bridge
USER nonroot:nonroot
ENTRYPOINT ["/metocean-bridge"]
