#include "pch.h"
#include "SKMP.h"

SKMP::SKMP(
	unsigned char masterKey[],
	int lenMasterKey,
	unsigned char seed[],
	int lenSeed,
	unsigned char CID,
	unsigned char GID)
{
	this->masterKey = masterKey;
	this->lenMasterKey = lenMasterKey;

	this->seed = seed;
	this->lenSeed = lenSeed;

	this->CID = CID;
	this->GID = GID;

	this->lenCurrentKey = CURR_KEY_LEN;

	this->hashHandler = new SHA();
}

SKMP::~SKMP()
{
	if (this->hashHandler)
		this->hashHandler->reset();

	if (this->hmacHandler)
		delete this->hashHandler;

	memset(this->masterKey, 0, MASTER_KEY_LEN);
	memset(this->seed, 0, SEED_LEN);
	memset(this->currentKey, 0, CURR_KEY_LEN);
}

int SKMP::setup()
{
	if (lenMasterKey != MASTER_KEY_LEN)
		return 1;

	if (lenSeed != SEED_LEN)
		return 2;

	if (this->hashHandler->setup() != 0)
		return 3;

	memcpy(this->currentKey, this->seed, SEED_LEN);

	return 0;
}

int SKMP::generateKey(
	unsigned char timestamp,
	unsigned char macTrunc[],
	int length)
{
	if (lenCurrentKey != CURR_KEY_LEN)
		return 1;

	unsigned char buffer[sizeof(CID) + sizeof(GID) + sizeof(timestamp)];

	int retVal = this->derivateKey();

	if (retVal != 0)
		return retVal;

	buffer[0] = CID;
	buffer[1] = GID;
	buffer[2] = timestamp;

	this->hmacHandler = new HMAC(this->masterKey, MASTER_KEY_LEN);
	retVal = this->hmacHandler->setup();

	if (retVal != 0)
		return retVal;

	retVal = this->hmacHandler->sign(
		buffer,
		sizeof(CID) + sizeof(GID) + sizeof(timestamp));

	if (retVal != 0)
		return retVal;

	if (length != TRUNC_LEN)
		return 1;

	memcpy(macTrunc, this->hmacHandler->result(), TRUNC_LEN);

	delete this->hmacHandler;

	return 0;
}

int SKMP::verifySign(
	unsigned char macTrunc[],
	int length,
	unsigned char timestamp)
{
	int retVal = 0;
	int curr = 1;
	const size_t buffLen = sizeof(CID) + sizeof(GID) + sizeof(timestamp);

	unsigned char buffer[buffLen];
	unsigned char currKeyTrunc[TRUNC_LEN];

	buffer[0] = CID;
	buffer[1] = GID;
	buffer[2] = timestamp;

	while (curr <= this->retries)
	{
		this->hmacHandler = new HMAC(this->masterKey, MASTER_KEY_LEN);
		retVal = this->hmacHandler->setup();

		if (retVal != 0)
			return retVal;

		retVal = this->hmacHandler->sign(buffer, buffLen);

		if (retVal != 0)
			return retVal;

		memcpy(currKeyTrunc, this->hmacHandler->result(), TRUNC_LEN);

		if (memcmp(macTrunc, currKeyTrunc, TRUNC_LEN) != 0)
		{
			curr = curr + 1;
			timestamp = timestamp + 1;
		}
		else
		{
			retVal = this->derivateKey();

			if (retVal != 0)
				return retVal;
			return 0;
		}

	}

	if (curr == this->retries)
	{
		//sync
		return -1;
	}
	return 0;
}

int SKMP::derivateKey()
{
	unsigned char secret[KDF_BUFF_LEN];
	int retVal = 0;

	// Concatenate masterKey || currentKey
	memcpy(secret, this->masterKey, MASTER_KEY_LEN);
	memcpy(secret + MASTER_KEY_LEN, this->currentKey, SEED_LEN);

	// KDF: hash twice 
	// First hash
	this->hashHandler->reset();
	this->hashHandler->setup();
	retVal = this->hashHandler->hash(secret, KDF_BUFF_LEN);

	if (retVal != 0)
		return retVal;

	// Clean and reinit the hash handler
	this->hashHandler->reset();
	retVal = this->hashHandler->setup();

	if (retVal != 0)
		return retVal;

	// Second hash
	retVal = this->hashHandler->hash(this->hashHandler->result(),
		this->hashHandler->length());

	if (retVal != 0)
		return retVal;

	memcpy(this->currentKey, this->hashHandler->result(), CURR_KEY_LEN);

	// Increment the current key counter;
	this->keyCounter = this->keyCounter + 1;

	// Cleanup
	this->hashHandler->reset();
	return 0;
}


