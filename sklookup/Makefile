APP=bpf

.PHONY: build
build: gen $(APP)

.PHONY: run
run: build
	sudo ./$(APP)

.PHONY: gen
gen: sum vmlinux gen_pid_bpfel.go

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
	-rm go.sum
	sed 's/v.*/latest/g' -i go.mod

$(APP): main.go gen_pid_bpfel.go
	 go build 

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h

gen_pid_bpfel.go: pid.bpf.c
	go generate main.go

go.sum:
	go mod download github.com/cilium/ebpf






