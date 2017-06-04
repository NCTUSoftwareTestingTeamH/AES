CC = g++
BASEFILE = type.h
AESFILE = AESCONST.h AES256.h AES256.cpp
SHAFILE = SHA256.h SHA256.cpp
FEAPATH = ..

all: Brutal UnitTest

UnitTest: AES256 SHA256 UnitTesting.cpp
	$(CC) -o UnitTest AES256.o SHA256.o UnitTesting.cpp -D_AES256UnitTest_ -lgtest -g

AES256: $(FEAPATH)/$(BASEFILE) $(FEAPATH)/SHA256.h $(FEAPATH)/AESCONST.h $(FEAPATH)/AES256.h $(FEAPATH)/AES256.cpp
	$(CC) -c -o AES256.o $(FEAPATH)/AES256.cpp -g -D_AES256UnitTest_

SHA256: $(FEAPATH)/$(BASEFILE) $(FEAPATH)/SHA256.h $(FEAPATH)/SHA256.cpp
	$(CC) -c -o SHA256.o $(FEAPATH)/SHA256.cpp -g

clean:
	rm -f *.o
	rm -f Brutal
