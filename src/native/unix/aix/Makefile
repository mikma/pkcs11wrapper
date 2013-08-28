CC = gcc -Xlinker -b -Xlinker noquiet 
SOURCE_DIR = ../../common/
PLATFORM_SRC_INCLUDE = ../src/
PLATFORM_LIBRARIES = lib/
DEBUG_OUTPUT_DIR = debug/
RELEASE_OUTPUT_DIR = release/
TARGETS = debug release
#CFLAGS= -fPIC -fpack-struct -shared -L$(PLATFORM_LIBRARIES) -ljava -ljvm
CFLAGS= -fPIC -shared -L$(PLATFORM_LIBRARIES) -ljava -ljvm

all : $(TARGETS)

VPATH = $(SOURCE_DIR) $(INCLUDE_DIR)

phony:

.PHONY	: debug
debug : phony $(SOURCE_DIR)pkcs11wrapper.c $(INCLUDE_DIR)pkcs11wrapper.h
	mkdir -p $(DEBUG_OUTPUT_DIR)
	$(CC) -I $(PLATFORM_SRC_INCLUDE) -I $(SOURCE_DIR) -DUNIX -DDEBUG -g -o $(DEBUG_OUTPUT_DIR)libpkcs11wrapper.so $(SOURCE_DIR)pkcs11wrapper.c $(CFLAGS)

.PHONY	: release
release : phony $(SOURCE_DIR)pkcs11wrapper.c $(INCLUDE_DIR)pkcs11wrapper.h
	mkdir -p $(RELEASE_OUTPUT_DIR)
	$(CC) -I $(PLATFORM_SRC_INCLUDE) -I $(SOURCE_DIR) -DUNIX -o $(RELEASE_OUTPUT_DIR)libpkcs11wrapper.so $(SOURCE_DIR)pkcs11wrapper.c $(CFLAGS)
	
clean :
	rm -f $(DEBUG_OUTPUT_DIR)* $(RELEASE_OUTPUT_DIR)*
