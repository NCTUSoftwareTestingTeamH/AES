#include"type.h"
#include"SHA256.h"

using namespace std;
namespace
{
    UINT start_hash[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    UINT k[64]=
    {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    UINT rotateR(UINT num,int times)
    {
        if(times<1)return num;
        UINT ans=num;
        ans=(ans<<(32-times))|(ans>>times);
        return ans;
    }
}
void output(string& ans)
{
    for(UINT i=0;i<ans.size();++i)
    {
        char temp1=(ans[i]>>4)&15;
        char temp2=ans[i]&15;
        //printf("<%u>",ans[i]);
        printf("%c",temp1<10?temp1+48:temp1+55);
        printf("%c ",temp2<10?temp2+48:temp2+55);
    }
    printf("\n");
}
string sha256(string& str)
{
    string temp(str);
    temp.push_back(-128);
    UINT bitsize=temp.size()<<3;
    UINT addzerobit=((bitsize&511)<=448 ? 448-(bitsize&511): 512-(bitsize&511)+448);
    for(UINT i=0;i<(addzerobit>>3);++i)temp.push_back(0);
    for(UINT i=0;i<8;++i)temp.push_back( ( ((static_cast<uint64_t>(str.size())*8)>>((7-i)*8)) &255 ) );
    //
    UINT h0=start_hash[0];
    UINT h1=start_hash[1];
    UINT h2=start_hash[2];
    UINT h3=start_hash[3];
    UINT h4=start_hash[4];
    UINT h5=start_hash[5];
    UINT h6=start_hash[6];
    UINT h7=start_hash[7];
    //output(temp);
    for(UINT i=0;i<(temp.size()>>(9-3));++i)//512 bits a chunk
    {
        UINT w[64];
        for(UINT j=0;j<16;++j)
        {
            UINT num=0;
            num+=(255&temp[(i<<6)+(j<<2)+0])<<24;//use 255& to avoid 9th bit
            num+=(255&temp[(i<<6)+(j<<2)+1])<<16;
            num+=(255&temp[(i<<6)+(j<<2)+2])<<8;
            num+=(255&temp[(i<<6)+(j<<2)+3])<<0;
            w[j]=num;
            //printf("[%02x %02x %02x %02x] %08x ",temp[(i<<6)+(j<<2)+0],temp[(i<<6)+(j<<2)+1],temp[(i<<6)+(j<<2)+2],temp[(i<<6)+(j<<2)+3],num);
        }
        for(UINT j=16;j<64;++j)
        {
            UINT s0=rotateR(w[j-15],7) ^ rotateR(w[j-15],18) ^ (w[j-15]>>3);
            UINT s1=rotateR(w[j-2],17) ^ rotateR(w[j-2],19) ^ (w[j-2]>>10);
            w[j]=w[j-16]+s0+w[j-7]+s1;
        }
        UINT a=h0;
        UINT b=h1;
        UINT c=h2;
        UINT d=h3;
        UINT e=h4;
        UINT f=h5;
        UINT g=h6;
        UINT h=h7;
        
        for(UINT j=0;j<64;++j)
        {
            //printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",a,b,c,d,e,f,g,h);
            UINT S1=rotateR(e,6) ^ rotateR(e,11) ^ rotateR(e,25);
            //UINT ch=(e&f)^((~e)&g);
            UINT ch=(g ^ (e & (f ^ g)));
            UINT temp1=h+S1+ch+k[j]+w[j];
            UINT S0=rotateR(a,2) ^ rotateR(a,13) ^ rotateR(a,22);
            UINT maj=(a&b)^(a&c)^(b&c);
            UINT temp2=S0+maj;
            
            h=g;
            g=f;
            f=e;
            e=d+temp1;
            d=c;
            c=b;
            b=a;
            a=temp1+temp2;
            
        }
        h0+=a;
        h1+=b;
        h2+=c;
        h3+=d;
        h4+=e;
        h5+=f;
        h6+=g;
        h7+=h;
    }
    string ans(UINT(32),0);
    for(UINT i=0;i<4;++i)
    {
        ans[(0<<2)+3-i]=(h0>>(i<<3))&255;
        ans[(1<<2)+3-i]=(h1>>(i<<3))&255;
        ans[(2<<2)+3-i]=(h2>>(i<<3))&255;
        ans[(3<<2)+3-i]=(h3>>(i<<3))&255;
        ans[(4<<2)+3-i]=(h4>>(i<<3))&255;
        ans[(5<<2)+3-i]=(h5>>(i<<3))&255;
        ans[(6<<2)+3-i]=(h6>>(i<<3))&255;
        ans[(7<<2)+3-i]=(h7>>(i<<3))&255;
    }
    return ans;
}
