cmd_applets/built-in.o :=  clang -fpass-plugin=/home/nevin/sentinel-cc/src/compiler/build/SentinelPass.so -nostdlib -nostdlib  -r -o applets/built-in.o applets/applets.o
