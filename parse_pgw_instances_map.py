import json
import socket
import struct

# Load JSON from bpftool output (you can also load from a file)
with open("pgw_map.json") as f:
    data = json.load(f)

for entry in data:
    v = entry["value"]

    id = v["id"]
    weight = v["weight"]
    ip_raw = v["ipv4_addr"]
    port_raw = v["port"]
    last_used = v["last_used"]

    ip_str = socket.inet_ntoa(struct.pack("<I", ip_raw))
    port = socket.ntohs(port_raw)

    print(f"ID: {id}, Weight: {socket.ntohl(weight)}, IP: {ip_str}, Port: {port}, Last Used: {last_used}")