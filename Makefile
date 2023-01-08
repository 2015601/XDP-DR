# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
LLC ?= llc
CLANG ?= clang
CC ?= gcc

XDP_C = dr_kernel.c dr_tc.c
XDP_OBJ = ${XDP_C:.c=.o}
LIBBPF = ../libbpf
OBJECT_LIBBPF = ${LIBBPF}/src/libbpf.a
CTL_OBJ = dr_ctl.o
CTL = drctl
CFLAGS = -I${LIBBPF}/src

all: llvm-check $(XDP_OBJ) 

.PHONY: clean ctl $(CLANG) $(LLC)

ctl: $(CTL_OBJ) $(OBJECT_LIBBPF)
	$(CC) $(CFLAGS) -o $@ $< -L../libbpf/src -l:libbpf.a

$(CTL_OBJ): dr_ctl.c
	$(CC) -Wall $(CFLAGS) -g -O2 -c -o $@ $(COMMON_OBJS) $<


$(OBJECT_LIBBPF):
	make -C ${LIBBPF}/src

clean:
	rm -f $(XDP_OBJ)
	rm -f *.ll
	rm -f *~
	rm -f *.o
	rm -f ctl

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
