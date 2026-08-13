# Two stages: build with the full Go toolchain, ship just the binary.
# CGO_ENABLED=0 because modernc.org/sqlite is pure Go -- there is nothing
# here that needs a C toolchain, which is what keeps this cross-compiling
# cleanly and the final image tiny.

FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Pass --build-arg VERSION=v0.2.0 (or a git describe) at release time; left
# at its default of "dev" for a plain local build.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/reefterm/sync-server/internal/api.Version=${VERSION}" \
    -o /out/reefterm-sync ./cmd/reefterm-sync

FROM scratch

# CA certs, in case a future version of this server ever makes an outbound
# HTTPS call. Costs a few hundred KB now; costs a debugging session later if
# it's missing when something finally needs it.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/reefterm-sync /reefterm-sync

# Where the default REEFTERM_SYNC_DB_PATH points, so a named volume mounted
# here is all a self-hoster needs for their data to survive a redeploy.
VOLUME /data
ENV REEFTERM_SYNC_DB_PATH=/data/reefterm-sync.db
ENV REEFTERM_SYNC_LISTEN_ADDR=:8420

EXPOSE 8420

ENTRYPOINT ["/reefterm-sync"]
