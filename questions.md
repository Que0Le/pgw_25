# Follow-up Questions

After completing the application, please answer the following questions in the spaces provided:

1. How would you change the application to support the dynamic registration of PGWs?

Your answer:
```
Dynamic registration requires more logics, therefore using an userspace program with access to the `pgw__instances_list_map` map could be a significant help.
Foreseenable tasks: registration/deregistration, sort array to eliminates empty spots (reclaim), flag GW for slow start/warm-up or for gracefully removeval. Handle communication with GWs: ping back, update weight, temporary downtime for maintenance. 

```

2. If a PGW does not refresh its registration within 3 seconds, it is considered unavailable and no more packets should be forwarded to it. How would you implement this?

Your answer:
```
- To detect such incident: add a `last_seen` field which should be updated if the GW ping back, or successfully handles forwarding packets. With this field, an userspace controller can periodly check and remove/ping old gateway. Kernel program can also do that, but less effective because the current kernel program is run only in the event of packet arrival, which means checking is either too expensive (if rate is 1Mpps) or irrelevant due to great timeout (0pps)
- To perfrom the action: flags should be set shall a GW is considered unreliable and needs to be checked (which takes time). This GW will be ignored by kernel program. If it is indeed removed, its spot needs to be cleared/reclaimed, also in combination with other intermediate flags (warm-up, ...) to make the process more smooth. If the check turns out to be ok, the flag should be remove so the GW can return to operation.
```

3a. When applying for the Senior Software Engineer - Packet Gateway (Go) role:
Imagine that you are free to use any protocol between the Load Distributor and the PGW instances. What solution could you suggest for service discovery and inter-service communication?

3b. When applying for the Senior Software Engineer - Data Plane (eBPF) role:
How would you optimize the application for performance and what technology would you use to meet a 1M packet/second requirement?

Your answer:
```
- LB works in virtual and lo env, so no hardware support is available. 
- Improve searching time: Pre-calculate best gateway: Cache low-util GWs, Flag high-util GWs. Pre-allocating region of responsiblitty by source (based on region, hash of IP + port, ...). Sort list of GWs to eliminate empty spots.
- Batch processing: cache packets, although I have to admit that I need to research more about this approach.
- Prefer `BPF_MAP_TYPE_ARRAY ` over hashmap if possible.
- Prefer `PER_CPU` for counters. Also replicate the main GW list for each CPU. If list is too large, consider supplying a calculated, smaller list.
- Consider using AF_XDP to deliver payload directly to PGWs. Downsides: only works if GWs are in the same machine, and GW needs heavy modification.

```

Please provide detailed explanations for each of your answers.
