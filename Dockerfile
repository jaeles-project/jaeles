FROM golang:1.20-buster as builder
RUN go install github.com/jaeles-project/jaeles@latest
RUN apt update -qq \
    && apt install -y chromium && apt clean
WORKDIR /root/
EXPOSE 5000
RUN jaeles config init -y
ENTRYPOINT ["/go/bin/jaeles"]
