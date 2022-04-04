#include "pch.h"
#include "SHA.h"
#include<stdio.h>
#include <iostream>

SHA::SHA()
{
}

SHA::~SHA()
{
}

int SHA::setup()
{
	// Aquire a crypto context handler
	if (!CryptAcquireContext(
		&this->hCryptProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		return 1;
	}

	// Create a empty hash
	if (!CryptCreateHash(
		this->hCryptProv,
		CALG_SHA1,
		0,
		0,
		&this->hashHandler))
	{
		return 2;
	}

	return 0;
}

int SHA::hash(unsigned char buff[], int length)
{
	if (!this->hCryptProv)
		return 1;

	if (!this->hashHandler)
		return 2;

	BYTE* tmpBuff = new BYTE[length];
	memcpy(tmpBuff, buff, length);
	//for (int i = 0; i < length; i++)
	//	tmpBuff[i] = buff[i];

	if (!CryptHashData(
		this->hashHandler,
		tmpBuff,
		length,
		0))
	{
		return 3;
	}


	if (!CryptGetHashParam(
		this->hashHandler,          // handle of the HMAC hash object
		HP_HASHVAL,               // query on the hash value
		NULL,                     // filled on second call
		&this->dwDataLen,         // length, in bytes, of the hash
		0))
	{
		return 4;
	}

	this->pbHash = (BYTE*)malloc(this->dwDataLen);
	if (NULL == this->pbHash)
	{
		return 5;
	}

	if (!CryptGetHashParam(
		this->hashHandler,		   // handle of the HMAC hash object
		HP_HASHVAL,                // query on the hash value
		this->pbHash,              // pointer to the HMAC hash value
		&this->dwDataLen,          // length, in bytes, of the hash
		0))
	{
		return 6;
	}

	//printf("The hash is:  ");
	//for (DWORD i = 0; i < this->dwDataLen; i++)
	//{
	//	printf("%02x ", pbHash[i]);

	//}

	//printf("\n");
	//std::cout << pbHash;

	return 0;
}

void SHA::reset()
{
	if (this->hCryptProv)
		CryptReleaseContext(this->hCryptProv, 0);

	if (this->hashHandler)
		CryptDestroyHash(this->hashHandler);
}

PBYTE SHA::result()
{
	return this->pbHash;
}

DWORD SHA::length()
{
	return this->dwDataLen;
}

