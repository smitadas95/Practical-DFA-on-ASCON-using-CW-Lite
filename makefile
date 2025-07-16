# Makefile for ChipWhisperer SimpleSerial-ascon Program
#
#----------------------------------------------------------------------------

TARGET = simpleserial-ascon

# List C source files here.
SRC += ${TARGET}.c
SRC += aead.c
SRC+=$(wildcard $(CRYPTO_PATH)/*.c)
ASRC+=$(wildcard $(CRYPTO_PATH)/*.S)
EXTRAINCDIRS += $(CRYPTO_PATH)
EXTRA_OPTS = NO_EXTRA_OPTS

# -----------------------------------------------------------------------------
CFLAGS += -D$(EXTRA_OPTS)

${info Building for platform ${PLATFORM} with CRYPTO_TARGET=$(CRYPTO_TARGET)}

#Add simpleserial project to build
include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
