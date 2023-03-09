An eBPF code to allow traffic only at a specific TCP port (default 4040) for a given process name ("myprocess"). All the traffic to all other ports for only that process are be dropped.

`myprocess` tries to bind to two ports namely `4040` and `8080` . Our goal is to allow the `4040` port bind by prevent `8080` port bind. This is illustrated bellow. 

Now lets say we opened another process named "s" which performs the same operations. We would not drop port `8080` bind attempt and allow all packets.

![image](https://user-images.githubusercontent.com/83643646/224089064-3c00c390-c652-45f9-a6e6-9001fffc0c0a.png)

