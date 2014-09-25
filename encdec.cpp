#ifndef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#endif

#include <vector>
#include "encdec.h"

#ifdef __WIN32
#pragma warning(disable: 4530)
#pragma warning(disable: 4506)
#endif

const unsigned long ClientEncryptKeys[12] =
{
	0x0001F44F, 0x00028386,
	0x0001125B, 0x0001A192,
	0x00005BC1, 0x00002E87,
	0x00004D68, 0x0000354F,
	0x0000BD1D, 0x0000B455,
	0x00003B43, 0x00009239
};
const bool ClientEncryptKeysLoaded = 1;

const unsigned long ServerDecryptKeys[12] =
{
	0x0001F44F, 0x00028386,
	0x0001125B, 0x0001A192,
	0x00007B38, 0x000007FF,
	0x0000DEB3, 0x000027C7,
	0x0000BD1D, 0x0000B455,
	0x00003B43, 0x00009239
};
const bool ServerDecryptKeysLoaded = 1;

const unsigned long ClientDecryptKeys[12] =
{
	0x00011E6E, 0x0001ADA5,
	0x0001821B, 0x00029C32,
	0x00004673, 0x00007684,
	0x0000607D, 0x00002B85,
	0x0000F234, 0x0000FB99,
	0x00008A2E, 0x0000FC57
};
const bool ClientDecryptKeysLoaded = 1;

const unsigned long ServerEncryptKeys[12] =
{
	0x00011E6E, 0x0001ADA5,
	0x0001821B, 0x00029C32,
	0x00003371, 0x00004A5C,
	0x00008A9A, 0x00007393,
	0x0000F234, 0x0000FB99,
	0x00008A2E, 0x0000FC57
};
const bool ServerEncryptKeysLoaded = 1;


unsigned char const C3Keys[] =
{
    0x9B,0xA7,0x08,0x3F,0x87,0xC2,0x5C,0xE2,
	0xB9,0x7A,0xD2,0x93,0xBF,0xA7,0xDE,0x20
};

unsigned char const C2Keys[] =
{
    0xE7,0x6D,0x3A,0x89,0xBC,0xB2,0x9F,0x73,
    0x23,0xA8,0xFE,0xB6,0x49,0x5D,0x39,0x5D,
	0x8A,0xCB,0x63,0x8D,0xEA,0x7D,0x2B,0x5F,
	0xC3,0xB1,0xE9,0x83,0x29,0x51,0xE8,0x56
};

unsigned char const LoginKeys[] =
{
    0xFC, 0xCF, 0xAB
};

void DecXor32(unsigned char*Buff,int SizeOfHeader,int Len);
void EncXor32(unsigned char*Buff,int SizeOfHeader,int Len);
void EncDecLogin(unsigned char*Buff,int Len);

int DecryptC3(unsigned char*Dest,unsigned char*Src,int Len,unsigned long*Keys);
int EncryptC3(unsigned char*Dest,unsigned char*Src,int Len,unsigned long*Keys);
int DecC3Bytes(unsigned char*Dest,unsigned char*Src,unsigned long*Keys);
void EncC3Bytes(unsigned char*Dest,unsigned char*Src,int Len,unsigned long*Keys);
int HashBuffer(unsigned char*Dest,int Param10,unsigned char*Src,int Param18,int Param1c);
void ShiftBuffer(unsigned char*Buff,int Len,int ShiftLen);

int GetPacketSize(unsigned char * Packet);
int GetHeaderSize(unsigned char * Packet);

int GetDecodedSize(unsigned char * Packet);
int GetEncodedSize(unsigned char * Packet);

unsigned char * EncodeServerPacket(unsigned char * Source, int Serial);
unsigned char * DecodeServerPacket(unsigned char * Source, int &Serial);

unsigned char * EncodeClientPacket(unsigned char * Source, int Serial);
unsigned char * DecodeClientPacket(unsigned char * Source, int &Serial);

void DecodeXor32(unsigned char * Buff, int HeaderSize, int Length);
void EncodeXor32(unsigned char * Buff, int HeaderSize, int Length);
void XorThreeBytes(unsigned char * Buff, int Length);

void DecXor32(unsigned char*Buff,int SizeOfHeader,int Len)
{
	for(int i=Len-1;i>=0;i--)
	{
		Buff[i]^=(C2Keys[(i+SizeOfHeader)&31]^Buff[i-1]);
	}
}

void EncXor32(unsigned char*Buff,int SizeOfHeader,int Len)
{
	for(int i=0;i<Len;i++)
	{
		Buff[i]^=(C2Keys[(i+SizeOfHeader)&31]^Buff[i-1]);
	}
}

void EncDecLogin(unsigned char*Buff,int Len)
{
	for(int i=0;i<Len;i++)
	{
		Buff[i]=Buff[i]^LoginKeys[i%3];
	}
}

int DecryptC3(unsigned char*Dest,unsigned char*Src,int Len,unsigned long*Keys)
{
	if(Dest==0)
	{
		return 0;
	}
	unsigned char *TempDest=Dest,*TempSrc=Src;
	int DecLen=0;
	if(Len>0)
	{
		do
		{
			if(DecC3Bytes(TempDest,TempSrc,Keys)<0)
			{
				return 0;
			}
			DecLen+=11;
			TempSrc+=11;
			TempDest+=8;
		} while(DecLen<Len);
	}
	return Len*8/11;
}

int DecC3Bytes(unsigned char*Dest,unsigned char*Src,unsigned long*Keys)
{
	memset(Dest,0,8);
	unsigned long TempDec[4]={0};
	int j=0;
	int i=0;
	for(i=0;i<4;i++)
	{
		HashBuffer((unsigned char*)TempDec+4*i,0,Src,j,16);
		j+=16;
		HashBuffer((unsigned char*)TempDec+4*i,22,Src,j,2);
		j+=2;
	}
	for(i=2;i>=0;i--)
	{
		TempDec[i]=TempDec[i]^Keys[8+i]^(TempDec[i+1]&0xFFFF);
	}
	unsigned long Temp=0,Temp1;
	for(i=0;i<4;i++)
	{
		Temp1=((Keys[4+i]*(TempDec[i]))%(Keys[i]))^Keys[i+8]^Temp;
		Temp=TempDec[i]&0xFFFF;
		((unsigned short*)Dest)[i] =(unsigned short)(Temp1);
	}
	TempDec[0]=0;
	HashBuffer((unsigned char*)TempDec,0,Src,j,16);
	((unsigned char*)TempDec)[0]=((unsigned char*)TempDec)[1]^((unsigned char*)TempDec)[0]^0x3d;
	unsigned char XorByte=0xF8;
	for(i=0;i<8;i++)
	{
		XorByte^=Dest[i];
	}
	if(XorByte!=((unsigned char*)TempDec)[1])
	{
		return -1;
	}
	else
	{
		return ((unsigned char*)TempDec)[0];
	}
}

int HashBuffer(unsigned char*Dest,int Param10,unsigned char*Src,int Param18,int Param1c)
{
	int BuffLen=((Param1c+Param18-1)>>3)-(Param18>>3)+2;
	unsigned char *Temp=new unsigned char[BuffLen];
	Temp[BuffLen-1]=0;
	memcpy(Temp,Src+(Param18>>3),BuffLen-1);
	int EAX=(Param1c+Param18)&7;
	if(EAX)
	{
		Temp[BuffLen-2]&=(0xff)<<(8-EAX);
	}
	int ESI = Param18&7;
    int EDI=Param10&7;
	ShiftBuffer(Temp,BuffLen-1,-ESI);
	ShiftBuffer(Temp,BuffLen,EDI);
    unsigned char*TempPtr =(Param10>>3)+Dest;
	int LoopCount=BuffLen-1+(EDI>ESI);
	if(LoopCount)
	{
		for(int i=0;i<LoopCount;i++)
		{
			TempPtr[i] = TempPtr[i]|(Temp[i]);
		}
	}
	delete[] Temp;
	return Param10 + Param1c;
}

void ShiftBuffer(unsigned char*Buff,int Len,int ShiftLen)
{
	int i = 0;
	if(ShiftLen)
	{
		if(ShiftLen>0)
		{
			if(Len-1>0)
			{
				for (i=Len-1;i>0;i--)
				{
					Buff[i]=(Buff[i-1]<<(8-ShiftLen))|(Buff[i]>>(ShiftLen));
				}
			}
			Buff[0] = Buff[0]>>ShiftLen;
            return;
		}
		ShiftLen=-ShiftLen;
		if(Len-1>0)
		{
			for(i=0;i<Len-1;i++)
			{
				Buff[i] =(Buff[i+1]>>(8-ShiftLen))|(Buff[i]<<ShiftLen);
			}
		}
		Buff[Len-1] = Buff[Len-1]<<ShiftLen;
	}
}

int EncryptC3(unsigned char*Dest,unsigned char*Src,int Len,unsigned long*Keys)
{
	if(Dest==0)
	{
		return 0;
	}
	unsigned char *TempDest=Dest,*TempSrc=Src;
	int EncLen=Len;
	if(Len>0)
	{
		do
		{
			EncC3Bytes(TempDest,TempSrc,(EncLen>7)?8:EncLen,Keys);
			EncLen-=8;
			TempSrc+=8;
			TempDest+=11;
		} while(EncLen>0);
	}
	return Len*11/8;
}

void EncC3Bytes(unsigned char*Dest,unsigned char*Src,int Len,unsigned long*Keys)
{
	unsigned long Temp=0,TempEnc[4];
	int i = 0;
	for(i=0;i<4;i++)
	{
		TempEnc[i]=((Keys[i+8]^((unsigned short*)Src)[i]^Temp)*Keys[i+4])%Keys[i];
		Temp=TempEnc[i]&0xFFFF;
	}
	for(i=0;i<3;i++)
	{
		TempEnc[i]=TempEnc[i]^Keys[8+i]^(TempEnc[i+1]&0xFFFF);
	}
	int j=0;
	memset(Dest, 0, 11);
	for(i=0;i<4;i++)
	{
		j=HashBuffer(Dest,j,(unsigned char*)TempEnc+4*i,0,16);
		j=HashBuffer(Dest,j,(unsigned char*)TempEnc+4*i,22,2);
	}
	unsigned char XorByte=0xF8;
	for(i=0;i<8;i++)
	{
		XorByte^=Src[i];
	}
	((unsigned char*)&Temp)[1]=XorByte;
	((unsigned char*)&Temp)[0]=XorByte^Len^0x3D;
	HashBuffer(Dest,j,(unsigned char*)&Temp,0,16);
}

/////////////////////////////////////////

int GetDecodedSize(unsigned char * Packet)
{
	switch(Packet[0] & 0xFF)
	{
	case 0xC1:
	    return GetPacketSize(Packet);
	case 0xC3:
		return (((GetPacketSize(Packet) - 2) * 8) / 11) + 1;
	case 0xC2:
	    return GetPacketSize(Packet);
	case 0xC4:
		return (((GetPacketSize(Packet) - 3) * 8) / 11) + 2;
	default:
		return 0;
	}
}

int GetEncodedSize(unsigned char * Packet)
{
	switch(Packet[0] & 0xFF)
	{
	case 0xC1:
	    return GetPacketSize(Packet);
	case 0xC3:
		return (((GetPacketSize(Packet) - 1) * 11) / 8) + 2;
	case 0xC2:
	    return GetPacketSize(Packet);
	case 0xC4:
		return (((GetPacketSize(Packet) - 2) * 11) / 8) + 3;
	default:
		return 0;
	}
}

int GetHeaderSize(unsigned char * Packet)
{
	switch(Packet[0] & 0xFF)
	{
	case 0xC1:
	case 0xC3:
		return 2;
	case 0xC2:
	case 0xC4:
		return 3;
	}
	return -1;
}

int GetPacketSize(unsigned char * Packet)
{
	switch(Packet[0] & 0xFF)
	{
	case 0xC1:
	case 0xC3:
		return (Packet[1] & 0xFF);
	case 0xC2:
	case 0xC4:
		return ((Packet[1] & 0xFF) & 256) + (Packet[2] & 0xFF);
	}
	return -1;
}

unsigned char * DecodeWholePacket(unsigned char * Source, int & Serial, bool PassXor, unsigned long * Where)
{
	Serial = -1;

	int iPacketSize = GetPacketSize(Source);
	int iHeaderSize = GetHeaderSize(Source);
	if(iHeaderSize == -1 || iPacketSize == -1)
	{
		return NULL;
	}

	unsigned char * NewPacket = new unsigned char [GetDecodedSize(Source)+1];

	if (Source[0] == 0xC3 || Source[0] == 0xC4)
    {
        int iDecodedLength = DecryptC3(NewPacket+(iHeaderSize-1), Source+iHeaderSize, iPacketSize - iHeaderSize, Where);
        if(iDecodedLength == 0)
        {
            delete[] NewPacket;
            return NULL;
        }

        Serial = NewPacket[iHeaderSize-1];

        NewPacket[0] = Source[0];

        switch(Source[0] & 0xFF)
        {
        case 0xC3:
            NewPacket[1] = (iDecodedLength + (iHeaderSize - 1)) & 0xFF;
            if(PassXor)
            {
                DecodeXor32(&NewPacket[3], 3, NewPacket[1] - 3);
            }
            break;
        case 0xC4:
            NewPacket[1] = ((iDecodedLength + (iHeaderSize - 1)) & 0xFF00) >> 8;
            NewPacket[2] = ((iDecodedLength + (iHeaderSize - 1)) & 0xFF);
            if(PassXor)
            {
                DecodeXor32(&NewPacket[4], 4, (iDecodedLength + (iHeaderSize - 1)) - 4);
            }
            break;
        }
    }
    else
    {
		memcpy(NewPacket, Source, iPacketSize);
		if(PassXor)
		{
			DecodeXor32(&NewPacket[iHeaderSize+1], iHeaderSize+1, iPacketSize - (iHeaderSize+1));
		}
    }

	return NewPacket;
}

unsigned char * DecodeClientPacket(unsigned char * Source, int & Serial)
{
	Serial = -1;
	return DecodeWholePacket(Source, Serial, true, (unsigned long*)&ServerDecryptKeys[0]);
}

unsigned char * DecodeServerPacket(unsigned char * Source, int & Serial)
{
	Serial = -1;
	return DecodeWholePacket(Source, Serial, false, (unsigned long*)&ClientDecryptKeys[0]);
}

unsigned char * EncodeWholePacket(unsigned char * Source, int Serial, bool PassXor, unsigned long * Where)
{
	int iPacketSize = GetPacketSize(Source);
	int iHeaderSize = GetHeaderSize(Source);
	if(iHeaderSize == -1 || iPacketSize == -1)
	{
		return NULL; // packet inválido
	}

	if(Source[0] == 0xC1 || Source[0] == 0xC2)
	{
	    unsigned char * NewPacket = new unsigned char [GetEncodedSize(Source)+1];
	    memcpy(NewPacket, Source, iPacketSize);
	    // passar xor
	    if(PassXor)
        {
            EncodeXor32((unsigned char*)&NewPacket[iHeaderSize+1], iHeaderSize+1, iPacketSize - (iHeaderSize+1));
        }
		return NewPacket;
	}

	unsigned char* SourceTemp = new unsigned char[iPacketSize];
	memcpy(SourceTemp, Source, iPacketSize);

	if(PassXor)
	{
		EncodeXor32((unsigned char*)&SourceTemp[iHeaderSize+1], iHeaderSize+1, iPacketSize - (iHeaderSize+1));
	}

	SourceTemp[iHeaderSize-1] = Serial & 0xFF;

	unsigned char* NewPacket = new unsigned char[GetEncodedSize(Source)+1];
	int iEncodedLength = EncryptC3(NewPacket+(iHeaderSize), (SourceTemp+iHeaderSize)-1, (iPacketSize - iHeaderSize)+1, Where);

	delete[] SourceTemp;

	NewPacket[0] = Source[0] & 0xFF;

	switch(Source[0] & 0xFF)
	{
	case 0xC1:
	case 0xC3:
		NewPacket[1] = ((GetEncodedSize(Source) + 1) & 0xFF);
		break;
	case 0xC2:
	case 0xC4:
		NewPacket[1] = ((GetEncodedSize(Source) + 1) & 0xFF00) >> 8;
		NewPacket[2] = ((GetEncodedSize(Source) + 1) & 0xFF);
		break;
	}

	return NewPacket;
}

unsigned char * EncodeClientPacket(unsigned char * Source, int Serial)
{
	return EncodeWholePacket(Source, Serial, true, (unsigned long*)&ClientEncryptKeys[0]);
}

unsigned char * EncodeServerPacket(unsigned char * Source, int Serial)
{
	return EncodeWholePacket(Source, Serial, false, (unsigned long*)&ServerEncryptKeys[0]); //
}

void DecodeXor32(unsigned char * Buff, int HeaderSize, int Length)
{
	DecXor32(Buff, HeaderSize, Length);
	return;
}

void EncodeXor32(unsigned char * Buff, int HeaderSize, int Length)
{
	EncXor32(Buff, HeaderSize, Length);
	return;
}

void XorThreeBytes(unsigned char * Buff, int Length)
{
	EncDecLogin(Buff, Length);
	return;
}

///
/// Packets
///

int packet_size(unsigned char* buffer)
{
	int result = GetPacketSize((unsigned char*) buffer);
	return result;
}

int packet_encode_size(unsigned char* buffer)
{
	int result = GetEncodedSize((unsigned char*) buffer);
	return result;
}

packet packet_encode_client(unsigned char* buffer, int serial)
{
	packet pkt;
	int packetLength = packet_encode_size((unsigned char*) buffer);
	unsigned char* encodedPtr = EncodeClientPacket((unsigned char*)buffer, serial);
	if (encodedPtr != NULL)
	{
		for (int i = 0; i < packetLength; i++)
		{
			pkt.push_back(encodedPtr[i]);
		}
		delete[] encodedPtr;
	}
    return pkt;
}

packet packet_encode_server(unsigned char* buffer, int serial)
{
	packet pkt;
	int packetLength = GetEncodedSize((unsigned char*) buffer);
	unsigned char* encodedPtr = EncodeServerPacket((unsigned char*)buffer, serial);
	if (encodedPtr != NULL)
	{
		for (int i = 0; i < packetLength; i++)
		{
			pkt.push_back(encodedPtr[i]);
		}
		delete[] encodedPtr;
	}
    return pkt;
}

int packet_decode_size(unsigned char* buffer)
{
	int result = GetDecodedSize((unsigned char*) buffer);
	return result;
}

packet packet_decode_client(unsigned char* buffer, int& serial)
{
	std::vector<unsigned char> pkt;
	int packetLength = GetDecodedSize((unsigned char*) buffer);
	unsigned char* decodePtr = DecodeClientPacket((unsigned char*)buffer, serial);
	if (decodePtr != NULL)
	{
		for (int i = 0; i < packetLength; i++)
		{
			pkt.push_back(decodePtr[i]);
		}
		delete[] decodePtr;
	}
	return pkt;
}

packet packet_decode_server(unsigned char* buffer, int& serial)
{
	packet pkt;
	int packetLength = GetDecodedSize((unsigned char*) buffer);
	unsigned char* decodePtr = DecodeServerPacket((unsigned char*)buffer, serial);
	if (decodePtr != NULL)
	{
		for (int i = 0; i < packetLength; i++)
		{
			pkt.push_back(decodePtr[i]);
		}
		delete[] decodePtr;
	}
	return pkt;
}
