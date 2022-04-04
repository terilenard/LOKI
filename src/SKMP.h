#pragma once
#ifndef INCLUDE_SKMP_H
#define INCLUDE_SKMP_H

#include "SHA.h"
#include "HMAC.h"

// Following key lengths in bytes
#define MASTER_KEY_LEN 32 // 256 bit for master key
#define SEED_LEN 16	// 128 bit for seed
#define CURR_KEY_LEN 20 // 160 bit for SHA-1
#define TRUNC_LEN 8 // 64 bit truncated value for buffers
#define KDF_BUFF_LEN MASTER_KEY_LEN+SEED_LEN

class SKMP
{
public:

	SKMP(
		unsigned char masterKey[],
		int lenMasterKey,
		unsigned char seed[],
		int lenSeed,
		unsigned char CID,
		unsigned char GID);
	~SKMP();

	int setup();
	int generateKey(
		unsigned char timestamp,
		unsigned char macTrunc[],
		int length);

	int verifySign(
		unsigned char macTrunc[],
		int length,
		unsigned char timestamp);

private:

	int derivateKey();

	unsigned char* masterKey;
	unsigned char* seed;
	unsigned char currentKey[CURR_KEY_LEN];

	unsigned char CID;
	unsigned char GID;

	int lenMasterKey;
	int lenSeed;
	int lenCurrentKey;
	int keyCounter = 0;
	int retries = 3;

	SHA* hashHandler;
	HMAC* hmacHandler;
};

#endif