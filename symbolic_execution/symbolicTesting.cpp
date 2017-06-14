#include"../klee/klee/include/klee/klee.h"
#include"../AES256.h"
#include<string>

using namespace std;
int main()
{
	int SIZE;
	char* password;
	klee_make_symbolic(&SIZE,sizeof(SIZE),"SIZE");
	password = new char[SIZE];
	klee_make_symbolic(password,sizeof(password),"password");
	AES256 cipher(password,SIZE);
	return 0;
}

