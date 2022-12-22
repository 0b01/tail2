default:
	cargo xtask run --release
deploy:
	cargo xtask run --release --build --deploy