import json, subprocess
import socket
import struct
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', required=False, help='Input filename')

args = parser.parse_args()
filename = args.file
if filename:
    with open(filename) as f:
        data = json.load(f)
else:
    cmd = [
        "sudo",
        "bpftool",
        "map",
        "dump",
        "pinned",
        "/sys/fs/bpf/tc/globals/pgw__instances_list_map",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("bpftool command failed:", result.stderr)
        exit(1)

    data = json.loads(result.stdout)

for entry in data:
    v = entry["value"]

    id = v["id"]
    weight = v["weight"]
    ip_raw = v["ipv4_addr"]
    port_raw = v["port"]
    pkt_count = v["pkt_count"]
    last_used = v["last_used"]
    last_seen = v["last_seen"]

    ip_str = socket.inet_ntoa(struct.pack("<I", ip_raw))
    port = socket.ntohs(port_raw)

    print(f"ID: {id}, Weight: {socket.ntohl(weight)}, IP: {ip_str}, Port: {port}, pkt_count: {pkt_count}" +
          f", Last Used: {last_used}, last_seen: {last_seen}")