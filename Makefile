.PHONY: build ui test check docker clean

# Builds the frontend, then the static server binary that embeds it.
build: ui
	CGO_ENABLED=0 go build -trimpath -o bin/pki-dash ./cmd/pki-dash

ui:
	cd web && npm ci && npm run build

test:
	cd web && npm run check && npm test
	go vet ./...
	go test -race ./...

check: test
	./scripts/gen-notices.sh | diff -u THIRD_PARTY_NOTICES.md -
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
	cd web && npm audit --audit-level=high

docker:
	docker build --build-arg VERSION=$$(git describe --tags --always --dirty) -t pki-dash:local .
	./scripts/container-smoke.sh pki-dash:local

clean:
	rm -rf bin web/dist/assets web/dist/index.html web/dist/favicon.svg
