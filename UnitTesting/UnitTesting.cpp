#include<iostream>
#include"../type.h"
#include"../AES256.h"
#include"../AESCONST.h"
#include"gtest/gtest.h"
#include<string>
using namespace std;

class AES256UnitTest: public ::testing::Test
{
	public:
		AES256 *cipher;
	private:
		virtual void SetUp()
		{
			cipher = NULL;
			//string password("asdfghjkloiuytrg");
			//cipher = new AES256(password);
		}
		virtual void TearDown()
		{
			if(cipher!=NULL)
			{
				delete cipher;
			}
		}

};
/*
TEST_F(AES256UnitTest,WWWSSS)
{
	UC plaintext[17]="jdhfiruejfkvmcla";
	cipher->Public_ShiftRow(plaintext,0);
	cout<<plaintext<<endl;
	cipher->Public_inver_ShiftRow(plaintext,0);
	EXPECT_STREQ(reinterpret_cast<const char*>(plaintext),"jdhfiruejfkvmcla");
}
*/
TEST_F(AES256UnitTest,Rijndael_key_gen)
{
	UC RoundKey[15][16]={	
	{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
	{0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f},
	{0xa5,0x73,0xc2,0x9f,0xa1,0x76,0xc4,0x98,0xa9,0x7f,0xce,0x93,0xa5,0x72,0xc0,0x9c},
	{0x16,0x51,0xa8,0xcd,0x02,0x44,0xbe,0xda,0x1a,0x5d,0xa4,0xc1,0x06,0x40,0xba,0xde},
	{0xae,0x87,0xdf,0xf0,0x0f,0xf1,0x1b,0x68,0xa6,0x8e,0xd5,0xfb,0x03,0xfc,0x15,0x67},
	{0x6d,0xe1,0xf1,0x48,0x6f,0xa5,0x4f,0x92,0x75,0xf8,0xeb,0x53,0x73,0xb8,0x51,0x8d},
	{0xc6,0x56,0x82,0x7f,0xc9,0xa7,0x99,0x17,0x6f,0x29,0x4c,0xec,0x6c,0xd5,0x59,0x8b},
	{0x3d,0xe2,0x3a,0x75,0x52,0x47,0x75,0xe7,0x27,0xbf,0x9e,0xb4,0x54,0x07,0xcf,0x39},
	{0x0b,0xdc,0x90,0x5f,0xc2,0x7b,0x09,0x48,0xad,0x52,0x45,0xa4,0xc1,0x87,0x1c,0x2f},
	{0x45,0xf5,0xa6,0x60,0x17,0xb2,0xd3,0x87,0x30,0x0d,0x4d,0x33,0x64,0x0a,0x82,0x0a},
	{0x7c,0xcf,0xf7,0x1c,0xbe,0xb4,0xfe,0x54,0x13,0xe6,0xbb,0xf0,0xd2,0x61,0xa7,0xdf},
	{0xf0,0x1a,0xfa,0xfe,0xe7,0xa8,0x29,0x79,0xd7,0xa5,0x64,0x4a,0xb3,0xaf,0xe6,0x40},
	{0x25,0x41,0xfe,0x71,0x9b,0xf5,0x00,0x25,0x88,0x13,0xbb,0xd5,0x5a,0x72,0x1c,0x0a},
	{0x4e,0x5a,0x66,0x99,0xa9,0xf2,0x4f,0xe0,0x7e,0x57,0x2b,0xaa,0xcd,0xf8,0xcd,0xea},
	{0x24,0xfc,0x79,0xcc,0xbf,0x09,0x79,0xe9,0x37,0x1a,0xc2,0x3c,0x6d,0x68,0xde,0x36},
	};
	cipher = new AES256();
	UINT arrayError = 0;
	//
	UC* keyBlock = cipher->Public_AccessRoundKey(0);
	memcpy(keyBlock,RoundKey[0],16);
	keyBlock = cipher->Public_AccessRoundKey(1);
	memcpy(keyBlock,RoundKey[1],16);
	//
	cipher->Public_Rijndael_key();
	keyBlock = cipher->Public_AccessRoundKey(2);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[2][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(3);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[3][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(4);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[4][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(5);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[5][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(6);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[6][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(7);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[7][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(8);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[8][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(9);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[9][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(10);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[10][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(11);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[11][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(12);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[12][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(13);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[13][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	keyBlock = cipher->Public_AccessRoundKey(14);
	for(int j=0;j<16;++j)
	{
		arrayError = arrayError << 1;
		if(keyBlock[j]!=RoundKey[14][j])
			arrayError += 1;
	}
	EXPECT_EQ(0,arrayError);
	arrayError =0;
	delete cipher;
	cipher=NULL;
}

TEST_F(AES256UnitTest,AddRoundKey_test)
{
	cipher = new AES256();
	UC fakeRoundKey[16]={0xf0,0xe0,0xd0,0xc0,0xb0,0xa0,0x90,0x80,0x70,0x60,0x50,0x40,0x30,0x20,0x10,0x00};
	UC plainText[16]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x0f};
	UC ansText[16]={0xf1,0xe2,0xd3,0xc4,0xb5,0xa6,0x97,0x88,0x79,0x6a,0x5b,0x4c,0x3d,0x2e,0x1f,0x0f};
	UC* keyBlock = cipher->Public_AccessRoundKey(0);
	memcpy(keyBlock,fakeRoundKey,16);
	cipher->Public_AddRoundKey(plainText,0,0);
	ASSERT_EQ(plainText[0],ansText[0]);
	ASSERT_EQ(plainText[1],ansText[1]);
	ASSERT_EQ(plainText[2],ansText[2]);
	ASSERT_EQ(plainText[3],ansText[3]);
	ASSERT_EQ(plainText[4],ansText[4]);
	ASSERT_EQ(plainText[5],ansText[5]);
	ASSERT_EQ(plainText[6],ansText[6]);
	ASSERT_EQ(plainText[7],ansText[7]);
	ASSERT_EQ(plainText[8],ansText[8]);
	ASSERT_EQ(plainText[9],ansText[9]);
	ASSERT_EQ(plainText[10],ansText[10]);
	ASSERT_EQ(plainText[11],ansText[11]);
	ASSERT_EQ(plainText[12],ansText[12]);
	ASSERT_EQ(plainText[13],ansText[13]);
	ASSERT_EQ(plainText[14],ansText[14]);
	ASSERT_EQ(plainText[15],ansText[15]);
	delete cipher;
	cipher = NULL;
}


TEST_F(AES256UnitTest,ShiftRow_test)
{
	cipher = new AES256();
	UC plainText[16]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	cipher->Public_ShiftRow(plainText,0);
	ASSERT_EQ(plainText[0],0x00);
	ASSERT_EQ(plainText[1],0x05);
	ASSERT_EQ(plainText[2],0x0a);
	ASSERT_EQ(plainText[3],0x0f);
	ASSERT_EQ(plainText[4],0x04);
	ASSERT_EQ(plainText[5],0x09);
	ASSERT_EQ(plainText[6],0x0e);
	ASSERT_EQ(plainText[7],0x03);
	ASSERT_EQ(plainText[8],0x08);
	ASSERT_EQ(plainText[9],0x0d);
	ASSERT_EQ(plainText[10],0x02);
	ASSERT_EQ(plainText[11],0x07);
	ASSERT_EQ(plainText[12],0x0c);
	ASSERT_EQ(plainText[13],0x01);
	ASSERT_EQ(plainText[14],0x06);
	ASSERT_EQ(plainText[15],0x0b);
	cipher->Public_inver_ShiftRow(plainText,0);
	ASSERT_EQ(plainText[0],0x00);
	ASSERT_EQ(plainText[1],0x01);
	ASSERT_EQ(plainText[2],0x02);
	ASSERT_EQ(plainText[3],0x03);
	ASSERT_EQ(plainText[4],0x04);
	ASSERT_EQ(plainText[5],0x05);
	ASSERT_EQ(plainText[6],0x06);
	ASSERT_EQ(plainText[7],0x07);
	ASSERT_EQ(plainText[8],0x08);
	ASSERT_EQ(plainText[9],0x09);
	ASSERT_EQ(plainText[10],0x0a);
	ASSERT_EQ(plainText[11],0x0b);
	ASSERT_EQ(plainText[12],0x0c);
	ASSERT_EQ(plainText[13],0x0d);
	ASSERT_EQ(plainText[14],0x0e);
	ASSERT_EQ(plainText[15],0x0f);



	delete cipher;
	cipher = NULL;
}

TEST_F(AES256UnitTest,MixColumn_test)
{
	cipher = new AES256();
	UC plainText[16];
	memset(plainText,0,16);
	plainText[0] = 0x01;
	plainText[5] = 0x01;
	plainText[10] = 0x01;
	plainText[15] = 0x01;
	cipher->Public_MixColumn(plainText,0);
	ASSERT_EQ(plainText[0],0x02);
	ASSERT_EQ(plainText[1],0x01);
	ASSERT_EQ(plainText[2],0x01);
	ASSERT_EQ(plainText[3],0x03);
	ASSERT_EQ(plainText[4],0x03);
	ASSERT_EQ(plainText[5],0x02);
	ASSERT_EQ(plainText[6],0x01);
	ASSERT_EQ(plainText[7],0x01);
	ASSERT_EQ(plainText[8],0x01);
	ASSERT_EQ(plainText[9],0x03);
	ASSERT_EQ(plainText[10],0x02);
	ASSERT_EQ(plainText[11],0x01);
	ASSERT_EQ(plainText[12],0x01);
	ASSERT_EQ(plainText[13],0x01);
	ASSERT_EQ(plainText[14],0x03);
	ASSERT_EQ(plainText[15],0x02);
	cipher->Public_inver_MixColumn(plainText,0);
	ASSERT_EQ(plainText[0],0x01);
	ASSERT_EQ(plainText[1],0x00);
	ASSERT_EQ(plainText[2],0x00);
	ASSERT_EQ(plainText[3],0x00);
	ASSERT_EQ(plainText[4],0x00);
	ASSERT_EQ(plainText[5],0x01);
	ASSERT_EQ(plainText[6],0x00);
	ASSERT_EQ(plainText[7],0x00);
	ASSERT_EQ(plainText[8],0x00);
	ASSERT_EQ(plainText[9],0x00);
	ASSERT_EQ(plainText[10],0x01);
	ASSERT_EQ(plainText[11],0x00);
	ASSERT_EQ(plainText[12],0x00);
	ASSERT_EQ(plainText[13],0x00);
	ASSERT_EQ(plainText[14],0x00);
	ASSERT_EQ(plainText[15],0x01);
	delete cipher;
	cipher = NULL;
}

TEST_F(AES256UnitTest,SboxMap_test)
{
	cipher = new AES256();
	UC plainText[16]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	cipher->Public_SboxMap(plainText,0);
	ASSERT_EQ(plainText[0],0x63);
	ASSERT_EQ(plainText[1],0x7c);
	ASSERT_EQ(plainText[2],0x77);
	ASSERT_EQ(plainText[3],0x7b);
	ASSERT_EQ(plainText[4],0xf2);
	ASSERT_EQ(plainText[5],0x6b);
	ASSERT_EQ(plainText[6],0x6f);
	ASSERT_EQ(plainText[7],0xc5);
	ASSERT_EQ(plainText[8],0x30);
	ASSERT_EQ(plainText[9],0x01);
	ASSERT_EQ(plainText[10],0x67);
	ASSERT_EQ(plainText[11],0x2b);
	ASSERT_EQ(plainText[12],0xfe);
	ASSERT_EQ(plainText[13],0xd7);
	ASSERT_EQ(plainText[14],0xab);
	ASSERT_EQ(plainText[15],0x76);
	cipher->Public_inver_SboxMap(plainText,0);
	ASSERT_EQ(plainText[0],0x00);
	ASSERT_EQ(plainText[1],0x01);
	ASSERT_EQ(plainText[2],0x02);
	ASSERT_EQ(plainText[3],0x03);
	ASSERT_EQ(plainText[4],0x04);
	ASSERT_EQ(plainText[5],0x05);
	ASSERT_EQ(plainText[6],0x06);
	ASSERT_EQ(plainText[7],0x07);
	ASSERT_EQ(plainText[8],0x08);
	ASSERT_EQ(plainText[9],0x09);
	ASSERT_EQ(plainText[10],0x0a);
	ASSERT_EQ(plainText[11],0x0b);
	ASSERT_EQ(plainText[12],0x0c);
	ASSERT_EQ(plainText[13],0x0d);
	ASSERT_EQ(plainText[14],0x0e);
	ASSERT_EQ(plainText[15],0x0f);
	delete cipher;
	cipher = NULL;
}

int main(int argc,char** argv)
{
	::testing::InitGoogleTest(&argc,argv);
	return RUN_ALL_TESTS();
}
