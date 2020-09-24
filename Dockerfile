FROM golang:1.14.4-buster as builder
RUN GO111MODULE=on GOOS=linux go get -v -ldflags "-linkmode external -extldflags -static" github.com/jaeles-project/jaeles

FROM alpine:latest
WORKDIR /
COPY --from=builder /go/bin/jaeles /bin/jaeles
RUN jaeles config init
EXPOSE 5000
ENTRYPOINT ["/bin/jaeles"]
