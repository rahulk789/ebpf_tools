.PHONY: all
all: 
	(cd pid_matcher; make)
	(cd bpf_core_read; make)
.PHONY: clean
clean: 
	(cd pid_matcher; make clean)
	(cd bpf_core_read; make clean)



