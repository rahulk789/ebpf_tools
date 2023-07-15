package main

import (
	"log"
	"time"
    "fmt"
    "flag"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./pid.bpf.c -- -I/usr/include/bpf -I.


func main() {

    matchpid := flag.Int64("matchpid",1000,"pid to be matched")
    flag.Parse()
    fmt.Println("argument that you have given:", *matchpid)
    

