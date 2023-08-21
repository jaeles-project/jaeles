TARGET   ?= jaeles
GO       ?= go
GOFLAGS  ?= 
VERSION  := $(shell cat libs/version.go | grep 'VERSION =' | cut -d '"' -f 2 | sed 's/ /\-/g')

build:
	go install
	go build -ldflags="-s -w" -tags netgo -trimpath -buildmode=pie -o dist/$(TARGET)

release:
	go install
	@echo "==> Clean up old builds"
	rm -rf ./dist/*
	@echo "==> building binaries for for mac intel"
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -tags netgo -trimpath -buildmode=pie -o dist/$(TARGET)
	zip -9 -j dist/$(TARGET)-macos-amd64.zip dist/$(TARGET) && rm -rf ./dist/$(TARGET)
	@echo "==> building binaries for for mac M1 chip"
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -tags netgo -trimpath -buildmode=pie -o dist/$(TARGET)
	zip -9 -j dist/$(TARGET)-macos-arm64.zip dist/$(TARGET)&& rm -rf ./dist/$(TARGET)
	@echo "==> building binaries for linux intel build on mac"
	GOOS=linux GOARCH=amd64 CC="/usr/local/bin/x86_64-linux-musl-gcc" CGO_ENABLED=1 go build -ldflags="-s -w" -tags netgo -trimpath -buildmode=pie -o dist/$(TARGET)
	zip -9 -j dist/$(TARGET)-linux.zip dist/$(TARGET)&& rm -rf ./dist/$(TARGET)
	mv dist/$(TARGET)-macos-amd64.zip dist/$(TARGET)-$(VERSION)-macos-amd64.zip
	mv dist/$(TARGET)-macos-arm64.zip dist/$(TARGET)-$(VERSION)-macos-arm64.zip
	mv dist/$(TARGET)-linux.zip dist/$(TARGET)-$(VERSION)-linux.zip
run:
	$(GO) $(GOFLAGS) run *.go

fmt:
	$(GO) $(GOFLAGS) fmt ./...; \
	echo "Done."

test:
	$(GO) $(GOFLAGS) test ./... -v%