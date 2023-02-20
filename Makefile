# XDP Load Balance

LLC ?= llc
CLANG ?= clang
CC ?= gcc

LIBBPF = libbpf/src
OBJECT_LIBBPF = ${LIBBPF}/libbpf.a

LOADER = xlb_loader
CONTRL = xlb_adm

CFLAGS = -I${LIBBPF} -g -O0
LDFLAGS = -L$(LIBBPF) -l:libbpf.a -lelf -lz

LOADER_OBJ = xlb_load.o

ADM_OBJ = xlb_admin.o

XDP_OBJ = xlb_xdp_kernel.o \
	xlb_bpf_tc.o


all: llvm-check $(XDP_OBJ) loader admin

.PHONY: clean loader admin $(CLANG) $(LLC)

loader: $(OBJECT_LIBBPF) $(LOADER_OBJ)
	$(CC) -o $(LOADER) $(LOADER_OBJ) $(LDFLAGS)

admin: $(OBJECT_LIBBPF) $(ADM_OBJ)
	$(CC) -o $(CONTRL) $(ADM_OBJ) $(LDFLAGS)

$(OBJECT_LIBBPF):
	make -C ${LIBBPF}/src

clean:
	rm -f *.ll
	rm -f *~
	rm -f *.o
	rm -f ctl
	rm -f $(LOADER)
	rm -f $(CONTRL)

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(XDP_OBJ): %.o: %.c
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

.c.o:
	$(CC) -Wall $(CFLAGS) -c -o $@ $<
