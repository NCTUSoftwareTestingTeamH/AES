#include<iostream>
#include<cstring>
#include"../type.h"
#include"../AES256.h"

int main()
{
	AES256 empty;
	char password[]="This is a password.";
	AES256 construct1good(password,strlen(password));
	AES256 construct1bad(password,0);
	std::string passwordSTL(password);
	AES256 construct2good(passwordSTL);
	std::string emptySTL;
	AES256 construct2bad(emptySTL);
	UC data[1024];
	construct1good.Encrypte(data,15);
	construct1good.Encrypte(data,16);
	construct1good.Encrypte(data,1024);
	construct1good.Decrypte(data,1024);
	construct1good.Decrypte(data,16);
	construct1good.Decrypte(data,15);
	return 0;
}
