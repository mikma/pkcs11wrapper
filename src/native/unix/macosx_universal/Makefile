CC = gcc
SOURCE_DIR = ../../common/
PLATFORM_SRC_INCLUDE = ../src/
PLATFORM_LIBRARIES = lib/
VM_INCLUDE = /System/Library/Frameworks/JavaVM.framework/Headers
DEBUG_OUTPUT_DIR = debug/
RELEASE_OUTPUT_DIR = release/
TARGETS = debug release
ARCH = -arch ppc64 -arch ppc -arch i386 -arch x86_64

all : $(TARGETS)

VPATH = $(SOURCE_DIR) $(INCLUDE_DIR)

# we do not need '-fpack-struct' as option to get byte aligned structure members as required by PKCS#11,
# all PKCS#11 modules seem to be compiled without this option

.PHONY	: debug
debug : pkcs11wrapper.c pkcs11wrapper.h
	mkdir -p $(DEBUG_OUTPUT_DIR)
	$(CC) -fPIC -I $(VM_INCLUDE) -I $(PLATFORM_SRC_INCLUDE) -I $(SOURCE_DIR) -DUNIX $(ARCH) -DDEBUG -g -dynamiclib -o $(DEBUG_OUTPUT_DIR)libpkcs11wrapper.jnilib -framework JavaVM $(SOURCE_DIR)pkcs11wrapper.c -mmacosx-version-min=10.5 -isysroot/Developer/SDKs/MacOSX10.5.sdk -DMACOSX_DEPLOYMENT_TARGET=10.5

.PHONY	: release
release : pkcs11wrapper.c pkcs11wrapper.h
	mkdir -p $(RELEASE_OUTPUT_DIR)
	$(CC) -fPIC -I $(VM_INCLUDE) -I $(PLATFORM_SRC_INCLUDE) -I $(SOURCE_DIR) -DUNIX $(ARCH) -dynamiclib -o $(RELEASE_OUTPUT_DIR)libpkcs11wrapper.jnilib -framework JavaVM $(SOURCE_DIR)pkcs11wrapper.c -mmacosx-version-min=10.5 -isysroot/Developer/SDKs/MacOSX10.5.sdk -DMACOSX_DEPLOYMENT_TARGET=10.5

clean :
	rm -f $(DEBUG_OUTPUT_DIR)* $(RELEASE_OUTPUT_DIR)*
