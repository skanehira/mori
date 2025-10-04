build:
	@cargo build --release 

run-allow-net: build
	@sudo ./target/release/mori --allow-network www.google.com -- ping -c 1 www.google.com

run-deny-net: build
	@sudo ./target/release/mori -- ping -c 1 www.google.com

run-deny-file: build
	@sudo ./target/release/mori --deny-file-read README.md -- cat README.md

run-allow-file: build
	@sudo ./target/release/mori -- cat README.md > /dev/null && echo "ok"

test:
	@cargo nextest run
	@cargo test --doc

test-cov:
	@cargo llvm-cov nextest --html
