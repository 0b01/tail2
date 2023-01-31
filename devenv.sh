sudo apt update
sudo apt install build-essential pkg-config libssl-dev zlib1g-dev wget unzip libclang clang
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup install stable
rustup install nightly
rustup default nightly
# rustup target add x86_64-unknown-linux-gnu
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
rustup component add rust-src --toolchain nightly-aarch64-unknown-linux-gnu

# for arm64
# cargo install --no-default-features --features system-llvm bpf-linker
cargo install bpf-linker

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.2/install.sh | bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

nvm install 16
nvm use 16
pushd frontend
pushd speedscope
npm i
npm run build
popd
popd

# cargo xtask build-ebpf --release
# cargo build --target x86_64-unknown-linux-gnu --release
