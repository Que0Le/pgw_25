# Follow-up Questions

After completing the application, please answer the following questions in the spaces provided:

1. How would you change the application to support the dynamic registration of PGWs?

Your answer:
```




```

2. If a PGW does not refresh its registration within 3 seconds, it is considered unavailable and no more packets should be forwarded to it. How would you implement this?

Your answer:
```
- added a `last_seen` field. With this field, userspace controller can periodly check and remove/ping old gateway. Kernel program can ignore old gateway and select other one.



```

3a. When applying for the Senior Software Engineer - Packet Gateway (Go) role:
Imagine that you are free to use any protocol between the Load Distributor and the PGW instances. What solution could you suggest for service discovery and inter-service communication?

3b. When applying for the Senior Software Engineer - Data Plane (eBPF) role:
How would you optimize the application for performance and what technology would you use to meet a 1M packet/second requirement?

Your answer:
```




```

Please provide detailed explanations for each of your answers.
