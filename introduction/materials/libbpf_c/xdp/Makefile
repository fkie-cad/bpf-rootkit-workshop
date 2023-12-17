APP=counter

.PHONY: bpf vmlinux skel run clean

bpf: vmlinux
	# compile the eBPF code into an object file
	# -g will add some debugging information
	#  note: Kali needs special include directories (-I), remove them if needed for other distros
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c $(APP).bpf.c -o $(APP).bpf.o \
		-I/usr/src/linux-headers-6.1.0-kali5-common/arch/x86/include/uapi/ \
		-I/usr/src/linux-headers-6.1.0-kali5-amd64/arch/x86/include/generated/uapi/

vmlinux:
	# generate vmlinux.h via the eBPF Type Format (BTF) interface
	# this contains all the kernel symbols and their definitions
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

skel: bpf
	# generate the libbpf binding code for the exec eBPF program
	bpftool gen skeleton $(APP).bpf.o name $(APP) > $(APP).skel.h

run: $(APP)
	# eBPF programs require higher privileges to run
	echo "use bpftool to load and attach ${APP}.bpf.o to a network device"

clean:
	-rm -rf *.o *.skel.h vmlinux.h
