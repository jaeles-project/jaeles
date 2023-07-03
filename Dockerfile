FROM golang:1.16-buster as builder
RUN GO111MODULE=on GOOS=linux go get -ldflags "-linkmode external -extldflags -static" github.com/jaeles-project/jaeles

FROM alpine:latest
RUN apk add chromium
WORKDIR /
COPY --from=builder /go/bin/jaeles /bin/jaeles
EXPOSE 5000
RUN jaeles config init -y
ENTRYPOINT ["/bin/jaeles"]
