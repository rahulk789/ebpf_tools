APP=bpf

.PHONY: build
build: gen $(APP)

.PHONY: run
run: build
	sudo ./$(APP)

.PHONY: gen
gen: sum vmlinux gen_sk_bpfel.go create

.PHONY: vmlinux
vmlinux: vmlinux.h

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt main.go

.PHONY: clean
clean:
	-rm $(APP)
	-rm gen*
	-rm vmlinux.h
	-sudo rmdir /sys/fs/cgroup/cg1

$(APP): main.go gen_sk_bpfel.go
	 go build 

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h

gen_sk_bpfel.go: sk.bpf.c
	go generate main.go

create: 
	sudo mkdir /sys/fs/cgroup/cg1

go.sum:
	go mod download github.com/cilium/ebpf






