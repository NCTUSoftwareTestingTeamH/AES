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
	#ifdef _AES256UnitTest_
		void Public_Rijndael_key();
		void Public_AddRoundKey(UC*,UINT,UINT);
		void Public_ShiftRow(UC*,UINT);
		void Public_MixColumn(UC*,UINT);
		void Public_SboxMap(UC*,UINT);
		void Public_inver_ShiftRow(UC*,UINT);
		void Public_inver_MixColumn(UC*,UINT);
		void Public_inver_SboxMap(UC*,UINT);
		UC* Public_AccessRoundKey(UINT);
	#endif
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
