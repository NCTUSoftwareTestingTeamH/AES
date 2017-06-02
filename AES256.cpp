#include<iostream>
#include<cstring>
#include<vector>

#include"AES256.h"
#include"AESCONST.h"
#include"SHA256.h"
using namespace std;
AES256::AES256(){}
AES256::AES256(char* str,UINT size)
{
	if(size<1)cout<<"Empty key is invalid"<<endl;
	else
	{
		string temp(str);
		temp=sha256(temp);
		memcpy(Roundkey[0],&temp[0],32);
		Rijndael_key();
	}
}
AES256::AES256(string& str)
{
	UINT size=str.size();
	if(size<1)cout<<"Empty key is invalid"<<endl;
	else
	{
		string temp(sha256(str));
		memcpy(Roundkey[0],&temp[0],32);
		Rijndael_key();
	}
}
AES256::~AES256()
{
	for(UINT i=0;i<15;++i)
	{
		for(UINT j=0;j<16;++j)Roundkey[i][j]=0;
	}
}
void AES256::Encrypte(UC* str,UINT size)//size = n *16 | n is a non-negative inteager
{
	UINT block_num=size>>4;
	UINT base;
	for(UINT i=0;i<block_num;++i)
	{
		base=i<<4;
		AddRoundKey(str,base,0);
		for(unsigned int j=1;j<14;++j)//9 times
		{
			SboxMap(str,base);
			ShiftRow(str,base);
			MixColumn(str,base);
			AddRoundKey(str,base,j);
		}
		SboxMap(str,base);
		ShiftRow(str,base);
		AddRoundKey(str,base,14);
	}
}
void AES256::Decrypte(UC* str,UINT size)
{
	UINT block_num=size>>4;
	UINT base;
	for(UINT i=0;i<block_num;++i)
	{
		base=i<<4;
		//printf("10 ");
		AddRoundKey(str,base,14);
		inver_ShiftRow(str,base);
		inver_SboxMap(str,base);
		for(unsigned int j=13;j>0;--j)//9 times
		{
			AddRoundKey(str,base,j);
			inver_MixColumn(str,base);
			inver_ShiftRow(str,base);
			inver_SboxMap(str,base);
		}
		//printf("1\n");
		AddRoundKey(str,base,0);
	}
}
void AES256::Rijndael_key()
{
	char temp[4];
	int rconpos=1;
	int keynum=2;
	while(1)
	{
		//round 2 4 6 8 10 12 14
		//first word of roundkey
		memcpy(temp,&Roundkey[keynum-1][13],3);//copy and rotate
		temp[3]=Roundkey[keynum-1][12];//cpoy and rotate
		for(int i=0;i<4;++i)temp[i]=sbox_table[static_cast<uint8_t>(temp[i])];
		temp[0]^=Rcon[rconpos++];
		for(int i=0;i<4;++i)//i means (i+1)th word
		{
			for(int j=0;j<4;++j)temp[j]^=Roundkey[keynum-2][(i<<2)+j];
			memcpy(&Roundkey[keynum][(i<<2)],&temp[0],4);
		}
		++keynum;
		if(keynum>=15)break;
		//round 3 5 7 9 11 13
		//first word of roundkey
		for(int i=0;i<4;++i)temp[i]=sbox_table[static_cast<uint8_t>(temp[i])];
		for(int i=0;i<4;++i)//i means (i+1)th word
		{
			for(int j=0;j<4;++j)temp[j]^=Roundkey[keynum-2][(i<<2)+j];
			memcpy(&Roundkey[keynum][(i<<2)],&temp[0],4);
		}
		++keynum;
	}
}
void AES256::AddRoundKey(UC* str,UINT pos,UINT round)
{
	//printf("%u",pos);
	for(UINT i=0;i<16;++i)str[pos+i]^=Roundkey[round][i];
	//printf("\n");
}
void AES256::ShiftRow(UC* str,UINT pos)
{
//[00][04][08][12]
//[01][05][09][13]
//[02][06][10][14]
//[03][07][11][15]
	UC temp;
	for(int i=1;i<4;++i)
	{
		UC* ptr=str+pos+i;
		for(int k=0;k<i;++k)
		{
			temp=*ptr;
			*ptr=*(ptr+4);
			*(ptr+4)=*(ptr+8);
			*(ptr+8)=*(ptr+12);
			*(ptr+12)=temp;
		}
	}
}
void AES256::MixColumn(UC* str,UINT pos)
{
	UC temp[4];
	UINT base;
	for(UINT i=0;i<4;++i)
	{
		base=pos+(i<<2);
		temp[0]=mix_table_2[str[base+0]]^mix_table_3[str[base+1]]^str[base+2]^str[base+3];
		temp[1]=str[base+0]^mix_table_2[str[base+1]]^mix_table_3[str[base+2]]^str[base+3];
		temp[2]=str[base+0]^str[base+1]^mix_table_2[str[base+2]]^mix_table_3[str[base+3]];
		temp[3]=mix_table_3[str[base+0]]^str[base+1]^str[base+2]^mix_table_2[str[base+3]];
		str[base+0]=temp[0];
		str[base+1]=temp[1];
		str[base+2]=temp[2];
		str[base+3]=temp[3];
	}
}
void AES256::SboxMap(UC* str,UINT pos)
{
	for(UINT i=0;i<16;++i)str[pos+i]=sbox_table[str[pos+i]];
}
void AES256::inver_ShiftRow(UC* str,UINT pos)
{
	UC temp;
	for(int i=1;i<4;++i)
	{
		UC* ptr=str+pos+i;
		for(int k=0;k<i;++k)
		{
			temp=*(ptr+12);
			*(ptr+12)=*(ptr+8);
			*(ptr+8)=*(ptr+4);
			*(ptr+4)=*ptr;
			*ptr=temp;
		}
	}
}
void AES256::inver_MixColumn(UC* str,UINT pos)
{
	UC temp[4];
	UINT base;
	for(UINT i=0;i<4;++i)
	{
		base=pos+(i<<2);
		temp[0]=mix_table_14[str[base+0]]^mix_table_11[str[base+1]]^mix_table_13[str[base+2]]^mix_table_9[str[base+3]];
		temp[1]=mix_table_9[str[base+0]]^mix_table_14[str[base+1]]^mix_table_11[str[base+2]]^mix_table_13[str[base+3]];
		temp[2]=mix_table_13[str[base+0]]^mix_table_9[str[base+1]]^mix_table_14[str[base+2]]^mix_table_11[str[base+3]];
		temp[3]=mix_table_11[str[base+0]]^mix_table_13[str[base+1]]^mix_table_9[str[base+2]]^mix_table_14[str[base+3]];
		str[base+0]=temp[0];
		str[base+1]=temp[1];
		str[base+2]=temp[2];
		str[base+3]=temp[3];
	}
}
void AES256::inver_SboxMap(UC* str,UINT pos)
{
	for(UINT i=0;i<16;++i)str[pos+i]=inv_sbox_table[str[pos+i]];
}
