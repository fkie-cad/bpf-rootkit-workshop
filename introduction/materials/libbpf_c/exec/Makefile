APP=exec

.PHONY: $(APP) vmlinux bpf skel run clean

$(APP): skel
	# create the final ELF file 
	# link agains libpf and libelf
	# exec will contain exec.bpf.o as another ELF file (ELF file in ELF file)
	# -g will add some debugging information
	clang $(APP).c -g -lbpf -lelf -o $(APP)

vmlinux:
	# generate vmlinux.h via the eBPF Type Format (BTF) interface
	# this contains all the kernel symbols and their definitions
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf: vmlinux
	# compile the eBPF code into an object file
	# -g will add some debugging information
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c $(APP).bpf.c -o $(APP).bpf.o

skel: bpf
	# generate the libbpf binding code for the exec eBPF program
	bpftool gen skeleton $(APP).bpf.o name $(APP) > $(APP).skel.h

run: $(APP)
	# eBPF programs require higher privileges to run
	sudo ./$(APP)

clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)
