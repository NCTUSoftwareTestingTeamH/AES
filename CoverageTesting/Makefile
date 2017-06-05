all: Coverage

Coverage: AES256 CoverageTesting.cpp
	g++ -o CoverageTesting AES256.o SHA256.o CoverageTesting.cpp -fprofile-arcs -ftest-coverage -lgcov

AES256: SHA256 ../type.h ../AESCONST.h ../AES256.h ../AES256.cpp
	g++ -c -o AES256.o ../AES256.cpp -fprofile-arcs -ftest-coverage -lgcov

SHA256: ../type.h ../SHA256.h ../SHA256.cpp
	g++ -c -o SHA256.o ../SHA256.cpp
