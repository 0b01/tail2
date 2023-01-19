default:
	cargo xtask run --release
deploy:
	cargo xtask run --release --build --deploy
test:
	cargo xtask test --release
ui:
	+$(MAKE) -C frontend