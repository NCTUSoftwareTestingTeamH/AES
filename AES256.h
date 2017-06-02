#ifndef AES_256
#define AES_256 "AES256.h"
//
#include<string>
#include"type.h"

class AES256
{
	public:
		AES256();
		AES256(char*,UINT);
		AES256(std::string&);
		~AES256();
		void Encrypte(UC*,UINT);
		void Decrypte(UC*,UINT);
	private:
		//function
		void Rijndael_key();
		void AddRoundKey(UC*,UINT,UINT);
		void ShiftRow(UC*,UINT);
		void MixColumn(UC*,UINT);
		void SboxMap(UC*,UINT);
		void inver_ShiftRow(UC*,UINT);
		void inver_MixColumn(UC*,UINT);
		void inver_SboxMap(UC*,UINT);
		//data
		UC Roundkey[15][16];//256bit
};








#endif
