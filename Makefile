TARGET   ?= jaeles
PACKAGES ?= core libs
GO       ?= go
GOFLAGS  ?= 

run:
	$(GO) $(GOFLAGS) run *.go

fmt:
	$(GO) $(GOFLAGS) fmt ./...; \
	echo "Done."

test:
	$(GO) $(GOFLAGS) test ./... -v