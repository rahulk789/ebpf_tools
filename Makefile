.PHONY: all
all: 
	(cd pid_matcher; make)
	(cd bpf_core_read; make)
.PHONY: cli
cli:
	(go install github.com/spf13/cobra-cli@latest)
	(sudo go build -o /usr/bin/hive)
.PHONY: clean
clean: 
	(cd pid_matcher; make clean)
	(cd bpf_core_read; make clean)
	(sudo rm /usr/bin/hive)



