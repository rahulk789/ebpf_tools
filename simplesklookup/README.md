(Set up a network namespace if needed). \
Write A sklookup program using sockmap in order to divert traffic from port 4000 to port 5000 in a helloworld client-server model

Thought process:
* Create kernel space ebpf file with src port fd in sockmap and dest port defined. 
* Make sklookup program to redirect from 4000(src) to 5000(dest)
* Create userspace file , get sock fd of src and push to sock map.
* pin the map. link and load the ebpf prog to the kernel

