# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := ../../release
HEADER := $(abspath ../include/)

CLANG ?= clang
LLVM_STRIP ?= llvm-strip

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)


CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS := profile
APPS += $(BZS_APPS)
# Required by libblazesym
ALL_LDFLAGS += -lrt -ldl -lpthread -lm
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: title $(patsubst %.cpp, $(OUTPUT)/%.o, $(wildcard *.cpp))

.PHONY: title
title:
	@echo ===============================BASIC_MODULE===============================

.PHONY: clean
clean:
	$(call msg,CLEAN)

.PHONY: test
test:
	$(call msg,TEST)
	@echo $(patsubst %.c, $(OUTPUT)/%.o, $(wildcard *.c))

$(OUTPUT)/%.o: %.cpp
	$(call msg,CXX,$@)
	$(CXX) $(CFLAGS) $(INCLUDES) -c $(filter %.cpp,$^) -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
