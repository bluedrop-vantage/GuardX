FROM golang:1.22-alpine AS build
WORKDIR /src
# Build context = repo root.
COPY gateway ./gateway
WORKDIR /src/gateway
RUN CGO_ENABLED=0 go build -trimpath -o /out/guardx-gateway ./cmd/guardx-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/guardx-gateway /guardx-gateway
EXPOSE 8081
USER nonroot:nonroot
ENTRYPOINT ["/guardx-gateway"]
