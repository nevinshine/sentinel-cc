#!/bin/bash
set -e

# Sentinel-CC Experiment 4: Compilation Scale
# Downloads, builds, and measures scale across real-world applications

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$BASE_DIR")"
BENCH_DIR="$ROOT_DIR/benchmarks"
PASS_SO="$ROOT_DIR/src/compiler/build/SentinelPass.so"
DUMP_TOOL="$ROOT_DIR/sentinel-dump"

mkdir -p "$BENCH_DIR"
cd "$BENCH_DIR"

export CC="clang"
export CFLAGS="-O2 -fpass-plugin=$PASS_SO"
export CXX="clang++"
export CXXFLAGS="-O2 -fpass-plugin=$PASS_SO"

echo "### Experiment 4: Compilation Scale"
echo ""
echo "| Application | Build Time | Metadata Size (bytes) | Syscall Sites |"
echo "|-------------|------------|-----------------------|---------------|"

# 1. BusyBox
if [ ! -d "busybox-1.36.1" ]; then
    wget -q https://busybox.net/downloads/busybox-1.36.1.tar.bz2
    tar xf busybox-1.36.1.tar.bz2
fi
cd busybox-1.36.1
make defconfig > /dev/null 2>&1
# Busybox Makefile doesn't use standard CFLAGS easily, but we can override CC
START_TIME=$SECONDS
make CC="clang -fpass-plugin=$PASS_SO" -j4 > /dev/null 2>&1 || true
BUILD_TIME=$(($SECONDS - $START_TIME))
if [ -f "busybox_unstripped" ]; then
    SEC_SIZE=$(objdump -h busybox_unstripped | awk '/\.llvm\.syscall\.bounds/{print $3}')
    SIZE_DEC=$((16#$SEC_SIZE))
    COUNT=$($DUMP_TOOL --json busybox_unstripped | grep '"site"' | wc -l)
    echo "| BusyBox 1.36.1 | ${BUILD_TIME}s | $SIZE_DEC | $COUNT |"
else
    echo "| BusyBox 1.36.1 | Failed | - | - |"
fi
cd ..

# 2. curl
if [ ! -d "curl-8.4.0" ]; then
    wget -q https://curl.se/download/curl-8.4.0.tar.gz
    tar xf curl-8.4.0.tar.gz
fi
cd curl-8.4.0
./configure --disable-shared --enable-static > /dev/null 2>&1
START_TIME=$SECONDS
make -j4 > /dev/null 2>&1 || true
BUILD_TIME=$(($SECONDS - $START_TIME))
if [ -f "src/curl" ]; then
    SEC_SIZE=$(objdump -h src/curl | awk '/\.llvm\.syscall\.bounds/{print $3}')
    SIZE_DEC=$((16#$SEC_SIZE))
    COUNT=$($DUMP_TOOL --json src/curl | grep '"site"' | wc -l)
    echo "| curl 8.4.0 | ${BUILD_TIME}s | $SIZE_DEC | $COUNT |"
else
    echo "| curl 8.4.0 | Failed | - | - |"
fi
cd ..

# 3. Redis
if [ ! -d "redis-7.2.3" ]; then
    wget -q https://download.redis.io/releases/redis-7.2.3.tar.gz
    tar xf redis-7.2.3.tar.gz
fi
cd redis-7.2.3
START_TIME=$SECONDS
make CC="clang" CFLAGS="-O2 -fpass-plugin=$PASS_SO" -j4 > /dev/null 2>&1 || true
BUILD_TIME=$(($SECONDS - $START_TIME))
if [ -f "src/redis-server" ]; then
    SEC_SIZE=$(objdump -h src/redis-server | awk '/\.llvm\.syscall\.bounds/{print $3}')
    SIZE_DEC=$((16#$SEC_SIZE))
    COUNT=$($DUMP_TOOL --json src/redis-server | grep '"site"' | wc -l)
    echo "| Redis 7.2.3 | ${BUILD_TIME}s | $SIZE_DEC | $COUNT |"
else
    echo "| Redis 7.2.3 | Failed | - | - |"
fi
cd ..
