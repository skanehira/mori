build:
	@cargo build --release 

run-allow: build
	@sudo ./target/release/mori --allow-network www.google.com -- ping -c 1 www.google.com

run-deny: build
	@sudo ./target/release/mori -- ping -c 1 www.google.com

test:
	@cargo nextest run
	@cargo test --doc
