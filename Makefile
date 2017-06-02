CC = g++
BASEFILE = type.h
AESFILE = AESCONST.h AES256.h AES256.cpp
SHAFILE = SHA256.h SHA256.cpp

all: usage
usage: AES256 SHA256 usage.cpp
	$(CC) -o usage AES256.o SHA256.o usage.cpp
AES256: $(BASEFILE) $(AESFILE)
	$(CC) -c -o AES256.o AES256.cpp
SHA256: $(BASEFILE) $(SHAFILE)
	$(CC) -c -o SHA256.o SHA256.cpp
clean:
	rm -f *.o
	rm -f usage
