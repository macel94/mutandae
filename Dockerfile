# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
ARG BUILD_SHA=unknown
WORKDIR /src
COPY go.mod ./
COPY . .
# The exact source revision is baked into the binary so the site can link the
# GitHub commit that produced it (internal/buildinfo).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X github.com/mutandae/mutandae/internal/buildinfo.Revision=${BUILD_SHA}" -o /out/mutandae ./cmd/mutandae

FROM alpine:3.24
ARG BUILD_SHA=unknown
LABEL org.opencontainers.image.revision=$BUILD_SHA
RUN addgroup -S mutandae && adduser -S -G mutandae mutandae
COPY --from=build /out/mutandae /usr/local/bin/mutandae
USER mutandae
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/usr/local/bin/mutandae"]
