default:
	cargo xtask run --release
check:
	cargo xtask check --release
builddebug:
	cargo xtask run --build
deploy:
	cargo xtask run --release --build --deploy
test:
	cargo xtask test --release
ui:
	+$(MAKE) -C frontend