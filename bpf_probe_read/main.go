
//go:build linux
// +build linux

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./sk.bpf.c -- -I/usr/include/bpf -I.


func main() {
    if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

    kprobe,err := link.Kprobe("sys_execve",objs.PidMatcher, nil)
    if err!=nil {
        log.Fatalf("opening kprobe: %s",err)
    }
    defer kprobe.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()


    // The plan here is to store the current pid at 0 , and store 1 at index 1 if current pid matches pid given by user
    // The pid given by the user is stored at index 3 to be accessed by the user.
	
    const mapkey1 uint32 = 0
	const mapkey2 uint32 = 1
    for range ticker.C {
        var value1 uint64
        var value2 uint64
        // var value bpfPidstruct
		if err := objs.Pidcheck.Lookup(mapkey1, &value1); err != nil {
			log.Fatalf("reading map: %v", err)
		}
        if err := objs.Pidcheck.Lookup(mapkey2, &value2); err != nil {
			log.Fatalf("reading map: %v", err)
		}
        log.Printf("Current pid %d \t is pid matched?: %d \n",value1,value2)
    }
}

