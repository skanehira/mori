build:
	@cargo build --release 

run-allow-net: build
	@sudo RUST_LOG=info ./target/release/mori --allow-network www.google.com -- ping -c 1 www.google.com

run-deny-net: build
	@sudo RUST_LOG=info ./target/release/mori -- ping -c 1 www.google.com

run-deny-file: build
	@sudo RUST_LOG=info ./target/release/mori --deny-file-read README.md -- cat README.md

run-allow-file: build
	@sudo RUST_LOG=info ./target/release/mori -- cat README.md > /dev/null && echo "ok"

test:
	@cargo nextest run
	@cargo test --doc

test-cov:
	@cargo llvm-cov nextest --html

# Docker builder image commands
docker-builder-build:
	@docker build -f Dockerfile.builder -t mori-builder:latest .

docker-builder-build-amd64:
	@docker build -f Dockerfile.builder --platform linux/amd64 -t mori-builder:amd64 .

docker-builder-build-arm64:
	@docker build -f Dockerfile.builder --platform linux/arm64 -t mori-builder:arm64 .

docker-builder-build-multiarch:
	@docker buildx build -f Dockerfile.builder \
		--platform linux/amd64,linux/arm64 \
		-t mori-builder:latest \
		--load .

docker-build:
	@docker run --rm \
		-v $(PWD):/workspace \
		mori-builder:latest \
		cargo build --release

docker-shell:
	@docker run --rm -it \
		-v $(PWD):/workspace \
		mori-builder:latest \
		/bin/bash
