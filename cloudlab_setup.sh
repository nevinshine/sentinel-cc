#!/bin/bash
set -e

echo "Updating APT packages..."
sudo apt-get update

echo "Installing dependencies..."
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) make cmake python3-venv libelf-dev

echo "Setting up Sentinel-CC..."
cd ~/sentinel-cc
echo "Building Sentinel-CC LLVM Pass..."
cd src/compiler
mkdir -p build && cd build
cmake ..
make -j$(nproc)
cd ../../../

echo "Building eBPF loader..."
cd src/runtime
make
cd ../../

echo "Setting up Python venv for Rigorous Evaluation..."
cd eval
python3 -m venv venv
source venv/bin/activate
pip install matplotlib numpy pandas
cd ..

echo "CloudLab setup complete!"
