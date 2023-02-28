
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
    "fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
    	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/florianl/go-tc/internal/unix"
	"github.com/jsimonetti/rtnetlink"

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
    tcIface := "ExampleEBPF"

// Set up a dummy interface for the example.
rtnl, err := setupDummyInterface(tcIface)
if err != nil {
	fmt.Fprintf(os.Stderr, "could not setup dummy interface: %v\n", err)
	return
}
defer rtnl.Close()

devID, err := net.InterfaceByName(tcIface)
if err != nil {
	fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
	return
}
defer func(devID uint32, rtnl *rtnetlink.Conn) {
	if err := rtnl.Link.Delete(devID); err != nil {
		fmt.Fprintf(os.Stderr, "could not delete interface: %v\n", err)
	}
}(uint32(devID.Index), rtnl)

tcnl, err := tc.Open(&tc.Config{})
if err != nil {
	fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
	return
}
defer func() {
	if err := tcnl.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
	}
}()

qdisc := tc.Object{
	Msg: tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(devID.Index),
		Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
		Parent:  tc.HandleIngress,
		Info:    0,
	},
	Attribute: tc.Attribute{
		Kind: "clsact",
	},
}

if err := tcnl.Qdisc().Add(&qdisc); err != nil {
	fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", tcIface, err)
	return
}
// when deleting the qdisc, the applied filter will also be gone
defer tcnl.Qdisc().Delete(&qdisc)

// Handcraft a eBPF program for the example.
spec := ebpf.ProgramSpec{
	Name: "test",
	Type: ebpf.SchedCLS,
	Instructions: asm.Instructions{
		// set exit code to 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	},
	License: "GPL",
}

// Load the eBPF program into the kernel.
prog, err := ebpf.NewProgram(&spec)
if err != nil {
	fmt.Fprintf(os.Stderr, "failed to load eBPF program: %v\n", err)
	return
}

fd := uint32(prog.FD())
flags := uint32(0x1)

filter := tc.Object{
	tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(devID.Index),
		Handle:  0,
		Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
		Info:    0x300,
	},
	tc.Attribute{
		Kind: "bpf",
		BPF: &tc.Bpf{
			FD:    &fd,
			Flags: &flags,
		},
	},
}
if err := tcnl.Filter().Add(&filter); err != nil {
	fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
	return
}

		}
}
