# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/mutandae ./cmd/mutandae

FROM alpine:3.22
RUN addgroup -S mutandae && adduser -S -G mutandae mutandae
COPY --from=build /out/mutandae /usr/local/bin/mutandae
USER mutandae
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/usr/local/bin/mutandae"]
