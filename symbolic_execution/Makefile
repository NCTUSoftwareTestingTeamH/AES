CC = clang++
BASEFILE = type.h
AESFILE = AESCONST.h AES256.h AES256.cpp
SHAFILE = SHA256.h SHA256.cpp
FEAPATH = ..

all: SYMBOLIC

SYMBOLIC: AES256 SHA256 symbolicTesting.cpp
	$(CC) -emit-llvm -c -g AES256.o SHA256.o symbolicTesting.cpp -std=c++11

AES256: $(FEAPATH)/$(BASEFILE) $(FEAPATH)/SHA256.h $(FEAPATH)/AESCONST.h $(FEAPATH)/AES256.h $(FEAPATH)/AES256.cpp
	$(CC) -c -o AES256.o $(FEAPATH)/AES256.cpp -g -std=c++11

SHA256: $(FEAPATH)/$(BASEFILE) $(FEAPATH)/SHA256.h $(FEAPATH)/SHA256.cpp
	$(CC) -c -o SHA256.o $(FEAPATH)/SHA256.cpp -g -std=c++11

clean:
	rm -f *.o
