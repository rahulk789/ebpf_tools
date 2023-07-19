.PHONY: all
all: 
	(cd pid_matcher; make)
	(cd bpf_core_read; make)
.PHONY: cli
cli:
	(go mod init github.com/mwiater/golangcliscaffold)
	(go install github.com/spf13/cobra-cli@latest)
	(cobra-cli init)
.PHONY: clean
clean: 
	(cd pid_matcher; make clean)
	(cd bpf_core_read; make clean)



