//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./pid.bpf.c -- -I/usr/include/bpf -I.

func main() {

	matchpid := flag.Int64("matchpid", 1000, "pid to be matched")
	flag.Parse()
	fmt.Println("argument that you have given:", *matchpid)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kprobe, err := link.Kprobe("sys_execve", objs.PidMatcher, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobe.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Store the current pid at 0th index
	// Store 1 at 1th indext if current pid matches pid given by user, else store 2
	// Store pid given by the user at 2nd index.

	const mapkey0 uint32 = 0
	const mapkey1 uint32 = 1
	const mapkey2 uint32 = 2
	if err := objs.Pidcheck.Put(mapkey2, matchpid); err != nil {
		log.Fatalf("reading map: %v", err)
	}
	var count int = 0
	for range ticker.C {
		var value1 uint64
		var value2 uint64
		count = count + 1
		// var value bpfPidstruct
		if err := objs.Pidcheck.Lookup(mapkey0, &value1); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		if err := objs.Pidcheck.Lookup(mapkey1, &value2); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		// check if pid is matched or not
		if value2 == 1 {
			log.Printf("Current pid %d \t is pid matched? %s \n", value1, "No")
			continue
		}
		if count == 1 {
			continue
		}
		log.Printf("Current pid %d \t is pid matched? %s \n", value1, "Yes!!!")
	}
}
