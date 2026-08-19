# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
ARG BUILD_SHA=unknown
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/mutandae ./cmd/mutandae

FROM alpine:3.24
ARG BUILD_SHA=unknown
LABEL org.opencontainers.image.revision=$BUILD_SHA
RUN addgroup -S mutandae && adduser -S -G mutandae mutandae
COPY --from=build /out/mutandae /usr/local/bin/mutandae
USER mutandae
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/usr/local/bin/mutandae"]
