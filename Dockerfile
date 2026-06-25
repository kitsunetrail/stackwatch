# Build the static stackwatch binary.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/stackwatch ./cmd/stackwatch

# Final image is the official Trivy image (Trivy + its DB tooling already on PATH),
# so StackWatch shells out to a pinned trivy version (ADR-002).
FROM aquasec/trivy:0.71.2
COPY --from=build /out/stackwatch /usr/local/bin/stackwatch
# The base image's entrypoint is trivy; run stackwatch instead.
ENTRYPOINT ["stackwatch"]
CMD ["--config", "/etc/stackwatch/config.yml"]
