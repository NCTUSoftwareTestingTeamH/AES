#include<iostream>
#include"type.h"
#include"AES256.h"
#include<string>
using namespace std;
int main()
{
	UC plaintext[17]="abcdefghijklmnop";
	string password("bad password");
	AES256 cipher(password);
	cipher.Encrypte(plaintext,16);
	cipher.Decrypte(plaintext,16);
	cout<<plaintext<<endl;


}
