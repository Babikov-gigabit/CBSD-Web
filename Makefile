VERSION ?= $(shell sed -n 's/^var version = "\(.*\)"/\1/p' cmd/cbsd-web/main.go)
LDFLAGS  = -s -w -X main.version=$(VERSION)
GO      ?= go

.PHONY: build freebsd test vet dev clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o cbsd-web ./cmd/cbsd-web

# Static FreeBSD binaries (cross-compiled from any OS).
freebsd:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/cbsd-web-freebsd-amd64 ./cmd/cbsd-web
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/cbsd-web-freebsd-arm64 ./cmd/cbsd-web

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

# UI development without FreeBSD: fake workdir + fake cbsd, http://127.0.0.1:8099
dev: build
	$(GO) run ./tools/devfixture -dir /tmp/cbsd-dev/jails
	printf '{"listen":"127.0.0.1:8099","tls_auto":false,"data_dir":"/tmp/cbsd-dev/data","users_file":"/tmp/cbsd-dev/users.json","audit_log":"/tmp/cbsd-dev/audit.log","workdir":"/tmp/cbsd-dev/jails","dist_dir":"/tmp/cbsd-dev/dist","cbsd_command":["/bin/sh","$(CURDIR)/testdata/fake-cbsd"],"initenv_command":["/bin/sh","$(CURDIR)/testdata/fake-cbsd","initenv"]}' > /tmp/cbsd-dev/conf.json
	echo "dev-password-1" | ./cbsd-web -config /tmp/cbsd-dev/conf.json useradd admin -role admin
	@echo "login: admin / dev-password-1"
	CBSDWEB_DEV_TOOLS=$(CURDIR)/testdata/fake-tools ./cbsd-web -config /tmp/cbsd-dev/conf.json -allow-root serve

clean:
	rm -rf cbsd-web bin
