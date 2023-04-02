default:
	cargo xtask run --release
check:
	cargo xtask check --release
build:
	cargo xtask run --build --release
builddebug:
	cargo xtask run --build
deploy:
	cargo xtask run --release --build --deploy
test:
	cargo xtask test --release $(filter)
ui:
	+$(MAKE) -C frontend