- I am not sure about the practice of backing-up pointer and value of UDP/IP headers. I know that advancing a pointer makes that pointer proned to be rejected by the verifier, but it seems to be not always the case, at least from my observation.

DUMP

```bash

clang -O2 -g -Wall -target bpf -c udp_count_kern.c -o udp_count_kern.o

sudo ip link set dev lo xdp obj udp_count_kern.o sec xdp
# view bpf log
sudo cat /sys/kernel/debug/tracing/trace_pipe

# view map
sudo bpftool map lookup id 31 key hex 00 00 00 00 >> map.json

sudo python3 get_counts.py
sudo nc -ul 2152

./ldtest -msgRate 1000

sudo ip link show dev lo
sudo ip link set dev lo xdp off
# list all xdp programs
sudo bpftool prog
sudo bpftool prog detach id <ID> dev lo
sudo bpftool map show


# pinned map
sudo rm /sys/fs/bpf/tc/globals/pgw__udp_count_map /sys/fs/bpf/tc/globals/pgw__instances_list_map
sudo rm /sys/fs/bpf/tc/globals/pgw__instances_list_map
```