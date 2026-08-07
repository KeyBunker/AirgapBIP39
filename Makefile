# AirgapBIP39 build
#   make       -> native Linux/macOS build (auto-detected)
#   make arm   -> Linux ARM64 cross-build
#   make win64 -> Windows 64-bit MinGW cross-build
#   make mac   -> explicit macOS build with clang

APP       := AirgapBip39
SRC_MAIN  := AirgapBip39.c
SRC_QR    := qr/qr.c

SRC_SHA := \
    sha/sha256.c \
    sha/sha512.c \
    sha/hmac_sha512.c \
    sha/pbkdf2.c

SRC_ARGON := argon2/argon2.c \
             argon2/core.c \
             argon2/encoding.c \
             argon2/thread.c \
             argon2/opt.c \
             argon2/blake2/blake2b.c

SRC_ARGON_ARM := argon2/argon2.c \
                 argon2/core.c \
                 argon2/encoding.c \
                 argon2/thread.c \
                 argon2/blake2/blake2b.c \
                 argon2/ref.c

SRC_SECP := \
    secp256k1/src/secp256k1.c \
    secp256k1/src/precomputed_ecmult.c \
    secp256k1/src/precomputed_ecmult_gen.c

CFLAGS_SECP :=

COMMON_INC := \
    -I. \
    -Isha \
    -Iargon2 \
    -Iargon2/blake2 \
    -Isecp256k1/include \
    -Isecp256k1/src \
    -Iqr

WARNINGS := -Wall -Wextra -Wformat=2 -Wformat-security -Wshadow -Wconversion -Wno-unused-function
HARDEN_C := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -fno-common

# Vendored libraries have a few benign warnings under modern compilers.
CFLAGS_ARGON := -Wno-type-limits -Wno-sign-compare -Wno-conversion

UNAME_S := $(shell uname -s 2>/dev/null)
ifeq ($(UNAME_S),Darwin)
SRC_ARGON_NATIVE := $(SRC_ARGON_ARM)
CFLAGS_NATIVE := -std=c11 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) \
    -DARGON2_NO_SSE2 -DARGON2_NO_SIMD -DARGON2_REF=1 -pthread
LDFLAGS_NATIVE := -pthread
else
SRC_ARGON_NATIVE := $(SRC_ARGON)
CFLAGS_NATIVE := -std=c11 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) -pthread
LDFLAGS_NATIVE := -Wl,-z,relro,-z,now,-z,noexecstack -pie -pthread
endif

ARM64_CC := aarch64-linux-gnu-gcc
CFLAGS_ARM64 := -std=c11 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) \
    -DARGON2_NO_SSE2 -DARGON2_NO_SIMD -DARGON2_REF=1 -pthread
LDFLAGS_ARM64 := -Wl,-z,relro,-z,now,-z,noexecstack -pie -pthread


MAC_CC ?= clang
CFLAGS_MAC := -std=c11 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) \
    -DARGON2_NO_SSE2 -DARGON2_NO_SIMD -DARGON2_REF=1 -pthread
LDFLAGS_MAC := -pthread

WIN64_CC := x86_64-w64-mingw32-gcc
CFLAGS_WIN64 := -std=c11 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) \
    -DSECP256K1_STATIC \
    -fstack-protector-strong -fno-common $(CFLAGS_ARGON)
LDFLAGS_WIN64 := -static \
    -Wl,--dynamicbase,--nxcompat,--high-entropy-va \
    -lws2_32 -lbcrypt

all: $(APP)

$(APP): $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON_NATIVE) $(SRC_SECP) $(SRC_SHA)
	$(CC) $(CFLAGS_NATIVE) $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON_NATIVE) $(SRC_SECP) $(SRC_SHA) -o $(APP) $(LDFLAGS_NATIVE)

arm:
	$(ARM64_CC) $(CFLAGS_ARM64) $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON_ARM) $(SRC_SECP) $(SRC_SHA) \
		-o $(APP)_arm64 $(LDFLAGS_ARM64)

mac:
	$(MAC_CC) $(CFLAGS_MAC) $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON_ARM) $(SRC_SECP) $(SRC_SHA) \
		-o $(APP)_mac $(LDFLAGS_MAC)

win64:
	$(WIN64_CC) $(CFLAGS_WIN64) $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON) $(SRC_SECP) $(SRC_SHA) \
		-o $(APP).exe $(LDFLAGS_WIN64)

self-test: $(APP)
	./$(APP) --self-test

clean:
	rm -f $(APP) $(APP).exe $(APP)_arm64 $(APP)_mac $(APP)_san
