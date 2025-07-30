

DUMP

```bash

clang -O2 -g -Wall -target bpf -c udp_count_kern.c -o udp_count_kern.o

sudo ip link set dev lo xdp obj udp_count_kern.o sec xdp

sudo bpftool map lookup id 4 key hex 00 00 00 00 >> map.json

sudo python3 get_counts.py
sudo nc -ul 2152

./ldtest -msgRate 1000

sudo ip link show dev lo
sudo ip link set dev lo xdp off
# list all xdp programs
sudo bpftool prog
sudo bpftool prog detach id <ID> dev lo
sudo bpftool map show

```