SHELL=/bin/bash -o pipefail

VERSION=0.5.3
TARGETS=linux/amd64 windows/amd64 darwin/amd64

GO ?= go
DOCKER ?= docker

export GO111MODULE=on
PWD=$(shell pwd)
LDFLAGS := -s -X github.com/vchain-us/vcn/pkg/meta.version=v${VERSION}
TEST_FLAGS ?= -v -race
VCNEXE=vcn-v${VERSION}-windows-4.0-amd64.exe
SETUPEXE=codenotary_vcn_v${VERSION}_setup.exe

.PHONY: vcn
vcn:
	$(GO) build ./cmd/vcn

.PHONY: vendor
vendor:
	$(GO) mod vendor

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...

.PHONY: install
install: TEST_FLAGS=-v
install: vendor test
	$(GO) install -ldflags '${LDFLAGS}' ./cmd/vcn

.PHONY: static
static:
	$(GO) build -a -tags netgo -ldflags '${LDFLAGS} -extldflags "-static"' ./cmd/vcn

.PHONY: docs/cmd
docs/cmd:
	rm -rf docs/cmd/*.md
	$(GO) run docs/cmd/main.go

.PHONY: build/xgo
build/xgo:
	$(DOCKER) build \
			-f ./build/xgo/Dockerfile \
			-t vcn-xgo \
			./build/xgo

.PHONY: build/makensis
build/makensis:
	$(DOCKER) build \
		-f ./build/makensis/Dockerfile \
		-t vcn-makensis \
		./build/makensis

.PHONY: clean/dist
clean/dist: 
	rm -Rf ./dist

.PHONY: clean
clean: clean/dist
	rm -f ./vcn

.PHONY: CHANGELOG.md
CHANGELOG.md:
	git-chglog -o CHANGELOG.md

.PHONY: CHANGELOG.md.next-tag
CHANGELOG.md.next-tag:
	git-chglog -o CHANGELOG.md --next-tag v${VERSION}

.PHONY: dist
dist: clean/dist build/xgo
	mkdir -p dist
	$(DOCKER) run --rm \
			-v ${PWD}/dist:/dist \
			-v ${PWD}:/source:ro \
			-e GO111MODULE=on \
			-e FLAG_LDFLAGS="${LDFLAGS}" \
			-e TARGETS="${TARGETS}" \
			-e PACK=cmd/vcn \
			-e OUT=vcn-v${VERSION} \
			vcn-xgo .

.PHONY: dist/${VCNEXE} dist/${SETUPEXE}
dist/${VCNEXE} dist/${SETUPEXE}:
	echo ${SIGNCODE_PVK_PASSWORD} | $(DOCKER) run --rm -i \
		-v ${PWD}/dist:/dist \
		-v ${SIGNCODE_SPC}:/certs/f.spc:ro \
		-v ${SIGNCODE_PVK}:/certs/f.pvk:ro \
		mono:5.20 signcode \
		-spc /certs/f.spc -v /certs/f.pvk \
		-a sha1 -$ commercial \
		-n "CodeNotary vcn" \
		-i https://codenotary.io/ \
		-t http://timestamp.comodoca.com -tr 10 \
		$@
	rm -Rf $@.bak

.PHONY: dist/NSIS
dist/NSIS: build/makensis
	mkdir -p dist/NSIS
	cp -f ./dist/${VCNEXE} ./dist/NSIS/vcn.exe
	cp -f ./build/NSIS/* ./dist/NSIS/
	sed -e "s/{VCN_VERSION}/v${VERSION}/g" ./build/NSIS/setup.nsi > ./dist/NSIS/setup.nsi
	$(DOCKER) run --rm \
			-v ${PWD}/dist/NSIS/:/app \
			vcn-makensis /app/setup.nsi
	mv -f ./dist/NSIS/*_setup.exe ./dist/
	rm -Rf ./dist/NSIS

.PHONY: dist/sign
dist/sign: vendor vcn
	for f in ./dist/*; do ./vcn sign -p $$f; printf "\n\n"; done

.PHONY: dist/all
dist/all: dist dist/${VCNEXE} dist/NSIS dist/${SETUPEXE}