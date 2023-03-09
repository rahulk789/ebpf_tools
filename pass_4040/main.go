
//go:build linux
// +build linux

package main

import (
    "net"
    "log"
    "fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
    "time"
    "golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type info bpf ./tcp.bpf.c -- -I/usr/include/bpf -I.


func main() {

    //matchpid := flag.Int64("matchpid",1000,"pid to be matched")
    //port := flag.Int64("port",4040,"port to be passed")
    //flag.Parse()
    //fmt.Println("pid that you have given: \n pid: %d port %d \n", *matchpid,*port)
    
    //comm := flag.("comm","c","comm to be filtered")
    //flag.Parse()
    //fmt.Println("comm that you have given: \n comm: %d \n", *comm)
    
    if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
    
    ifaceName := "lo"
	iface, _ := net.InterfaceByName(ifaceName)
	

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

    kprobe,err := link.Kprobe("security_socket_bind",objs.BindIntercept, nil)
    if err!=nil {
        log.Fatalf("opening kprobe: %s",err)
    }
    defer kprobe.Close()

    l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()
    log.Printf("Listening for events..")

    ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
    var event bpfInfo
    const key uint32 = 0
    for range ticker.C{
            if err := objs.Eventmap.Lookup(key, &event); err != nil {
		    	log.Println("reading map: %v", err)
                continue
	    	}
            fmt.Printf("pid: %d\n",event.Pid)
			fmt.Printf("dest port: %d\n",event.Lport)
 			fmt.Printf("src port: %d\n",event.Rport)
            fmt.Printf("comm: %s\n",unix.ByteSliceToString(event.Comm[:]))
            fmt.Printf("\n")
		}
}
