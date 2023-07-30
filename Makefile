.PHONY: all
all: make cli 
make:	
	(cd pid-matcher; make)
	(cd tcp-connect; make)
	(cd cgroup-counter; make)
.PHONY: cli
cli:
	(sudo go build -o /usr/bin/hive)
.PHONY: install
install:
	(go install github.com/spf13/cobra-cli@latest)
.PHONY: clean
clean: 
	(cd pid-matcher; make clean)
	(cd tcp-connect; make clean)
	(cd cgroup-counter; make clean)
	(sudo rm /usr/bin/hive)



