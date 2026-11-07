.PHONY: build test rules-test integration lint scan-fixture image image-test image-deps clean

# Build binary
build:
	CGO_ENABLED=0 go build -o bin/kscan ./cmd/kscan

# Run unit tests
test:
	go test ./... -count=1

# Validate custom semgrep rules against their ruleid/ok annotated targets
rules-test:
	cd rules && semgrep --test --metrics off .

# Run the real scanners on test-fixtures and check each catches its issue
integration: build
	go test -tags integration ./integration/ -count=1 -v

IMAGE ?= kscan:dev
VERSION ?= dev

# Build the scanner image for the local platform and report its size
image:
	docker buildx build --load --build-arg VERSION=$(VERSION) -t $(IMAGE) .
	@# docker image ls adds compressed blobs to unpacked layers; report each.
	@echo "$(IMAGE) unpacked: $$(docker run --rm --entrypoint du $(IMAGE) -sxm / | cut -f1) MB"
	@echo "$(IMAGE) compressed (pull size): $$(( $$(docker image inspect $(IMAGE) --format '{{.Size}}') / 1000000 )) MB"

# Run the integration tests through the image (gosec/govulncheck are not in it)
image-test:
	KSCAN_BIN=$(CURDIR)/scripts/kscan-docker KSCAN_IMAGE=$(IMAGE) \
		go test -tags integration ./integration/ -count=1 -v

# Re-lock the Python scanners after changing docker/requirements.in
image-deps:
	cd docker && uv pip compile requirements.in --universal --python-version 3.12 --generate-hashes -o requirements.txt

lint:
	gofmt -l . | (! grep .)
	@cmp ci/github/security-scan.yml .github/workflows/security-scan.yml || (echo "kscan dogfoods the CI template: keep both files identical"; exit 1)
	go vet ./...

# Scan the bundled vulnerable fixture (report goes to kscan-report/, gitignored)
scan-fixture: build
	./bin/kscan scan test-fixtures --fail-on none

clean:
	rm -rf bin kscan-report
