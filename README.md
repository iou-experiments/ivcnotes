# IOU-Cash

## How to compile and run basic test steps
1. Clone the repo
Terminal -> `git clone https://github.com/IOU-experiments/IOU-Cash.git`

2. Run Yarn to download needed circuits
Terminal -> `yarn`

3. Go to IOU circuit and compile the circuit
Terminal -> `circom iou.circom --r1cs --sym --wasm --prime vesta`

4. Run folding scheme test cases using Rust
Terminal -> `cargo test`

Will provide better documentation when project codebase is clear enough.
