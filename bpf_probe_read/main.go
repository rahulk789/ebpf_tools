
//go:build linux
// +build linux

package main

import (
//    "errors"
    "syscall"
    "os/signal"
    "os"
    "log"
    "bytes"
    "encoding/binary"
    "fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
    "github.com/cilium/ebpf/perf"
    "golang.org/x/sys/unix"

)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type info bpf ./pid.bpf.c -- -I/usr/include/bpf -I.


func main() {

    //matchpid := flag.Int64("matchpid",1000,"pid to be matched")
    //port := flag.Int64("port",4040,"port to be passed")
    //flag.Parse()
    //fmt.Println("argument that you have given: \n pid: %d port %d \n", *matchpid,*port)
    
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

    if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

    kprobe,err := link.Kprobe("sys_bind",objs.BindIntercept, nil)
    if err!=nil {
        log.Fatalf("opening kprobe: %s",err)
    }
    defer kprobe.Close()

    rd, err := perf.NewReader(objs.Pipe, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

    record:=make(chan []byte)
	var event bpfInfo
    go func() {
		for {
			eventss, err := rd.Read()
            if err != nil {
			    log.Fatalf("closing ringbuf reader: %s", err)
            }
           record <- eventss.RawSample
		}
	}()

	log.Printf("Listening for events..")
	for {   	
            go func() {
		        <-stopper
		        if err := rd.Close(); err != nil {
			    log.Fatalf("closing ringbuf reader: %s", err)
                }
	        }()

            raw := <-record 
            event.Pid =  binary.LittleEndian.Uint32(raw[0:32])
            event.Rport =  binary.BigEndian.Uint16(raw[40:42])
            event.Lport = binary.LittleEndian.Uint16(raw[36:38])
            fmt.Printf("pid: %d\n", event.Pid)
			fmt.Printf("dest port: %d\n", event.Lport)
        if err := binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, &event); err != nil {
		    	log.Printf("parsing perf event: %s", err)
                continue
		    }   
 			fmt.Printf("src port: %d\n", event.Rport)
               fmt.Printf("comm: %s\n",unix.ByteSliceToString(event.Comm[:]))
            //event.Comm =  binary.LittleEndian.Uint32(raw[32:64])
            fmt.Printf("\n")
		}
}
