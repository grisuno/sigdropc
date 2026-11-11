CC = x86_64-w64-mingw32-gcc
WINDRES = x86_64-w64-mingw32-windres
CFLAGS = -O2 -Wall -D_M_AMD64
LIBS = -lrpcrt4 -lole32 -lktmw32 -lshell32

all: sigdrop.exe

sigdrop_res.o: sigdrop.rc hid.dll
	$(WINDRES) sigdrop.rc -O coff -o $@

sigdrop.exe: sigdrop.c windefend_c.c windefend_h.h resource.h sigdrop_res.o
	$(CC) $(CFLAGS) -o $@ sigdrop.c windefend_c.c sigdrop_res.o $(LIBS)

debug: sigdrop_dbg.c windefend_c.c windefend_h.h resource.h sigdrop_res.o
	$(CC) $(CFLAGS) -o sigdrop_dbg.exe sigdrop_dbg.c windefend_c.c sigdrop_res.o $(LIBS)

clean:
	rm -f sigdrop.exe sigdrop_dbg.exe sigdrop_res.o

install-lab: sigdrop.exe
	cp sigdrop.exe "$$HOME/.winbox/shared/sigdrop.exe"
