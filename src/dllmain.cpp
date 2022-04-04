// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "cdll.h"
#include "VIA.h"
#include "VIA_CDLL.h"
#include "SKMP.h"

#include <map>

#define USECDLL_FEATURE
#define SHOULD_INIT 1
#define SHOULD_NOT_INIT 0
#define SUCCESS 0
#define DLL_ERROR 4
#define ARR_LENGTH_ERROR 8
#define INSTANCE_EXISTS 9
#define INSTANCE_NOT_FOUND 10

class Inst;

std::map<int, Inst*> instances;

int initInstance(int instanceKey,
	unsigned char masterKey[],
	int lenMasterKey,
	unsigned char seed[],
	int lenSeed,
	unsigned char CID,
	unsigned char GID);
int tearDownInstance(int instanceKey);

int CAPLEXPORT far CAPLPASCAL dll_InitInstance(int instanceKey,
	unsigned char masterKey[],
	int lenMasterKey,
	unsigned char seed[],
	int lenSeed,
	unsigned char CID,
	unsigned char GID);
int CAPLEXPORT far CAPLPASCAL dll_TearDownInstance(int instanceKey);
int CAPLEXPORT far CAPLPASCAL dll_SetupInstance(int instanceKey);
int CAPLEXPORT far CAPLPASCAL dll_GenerateKey(int instanceKey,
	unsigned char macTrunc[],
	int length,
	unsigned char timestamp);
int CAPLEXPORT far CAPLPASCAL dll_VerifyKey(int instanceKey,
	unsigned char macTrunc[],
	int length,
	unsigned char timestamp);
int CAPLEXPORT far CAPLPASCAL dll_MasterKeyLen();
int CAPLEXPORT far CAPLPASCAL dll_SeedLen();

CAPL_DLL_INFO4 table[] = {
{CDLL_VERSION_NAME,		(CAPL_FARCALL)CDLL_VERSION,			"",			"",			CAPL_DLL_CDECL,		0xabcd,		CDLL_EXPORT },
{"dll_InitInstance",    (CAPL_FARCALL)dll_InitInstance,	      "CAPL_DLL", "Creates a inst in map",         'i',	    7,	"iBiBibb",    "\0\1\0\1\0\0\0" },
{"dll_TearDownInstance",(CAPL_FARCALL)dll_TearDownInstance,	  "CAPL_DLL", "Destroys a inst from map",      'i',	    1,  "i",          "\0" },
{"dll_SetupInstance",   (CAPL_FARCALL)dll_SetupInstance,      "CAPL_DLL", "Setup SKMP. Call after init",   'i',     1,  "i",          "\0"},
{"dll_GenerateKey",     (CAPL_FARCALL)dll_GenerateKey,        "CAPL_DLL", "Generate new group key",        'i',     4,  "iBib",       "\0\1\0\0"},
{"dll_VerifyKey",       (CAPL_FARCALL)dll_VerifyKey,          "CAPL_DLL", "Verifies a MAC from g master",  'i',     4,  "iBib",       "\0\1\0\0"},
{"dll_MasterKeyLen",    (CAPL_FARCALL)dll_MasterKeyLen,       "CAPL_DLL", "Length of master key in bytes", 'i',     0,  "",           ""},
{"dll_SeedLen",         (CAPL_FARCALL)dll_SeedLen,            "CAPL_DLL", "Length of seed in bytes",       'i',     0,  "",           ""},
{0, 0}
};

CAPLEXPORT CAPL_DLL_INFO4 far* caplDllTable4 = table;

int WINAPI DllEntryPoint(HINSTANCE, unsigned long reason, void*)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		return 1; // Indicates that the DLL was initialized successfully
	case DLL_PROCESS_DETACH:
		return 2; // Indicates that the DLL was detached successfully
	}
	return 0;
}

class Inst
{
public:

	Inst(unsigned char masterKey[],
		int lenMasterKey,
		unsigned char seed[],
		int lenSeed,
		unsigned char CID,
		unsigned char GID)
	{
		this->protocolHandler = new SKMP(masterKey, lenMasterKey, seed, lenSeed, CID, GID);
	};

	~Inst()
	{
		if (this->protocolHandler)
			delete this->protocolHandler;
	};

	SKMP* protocolHandler;
};


int initInstance(int instanceKey, 
				unsigned char masterKey[],
				int lenMasterKey,
				unsigned char seed[],
				int lenSeed,
				unsigned char CID,
				unsigned char GID)
{
	// Returns a handler to a HmacFilter instance
	if (instances.count(instanceKey) != 1)
	{
		// Key not found, create new instance
		instances.insert(std::pair<int, Inst*>(instanceKey, new Inst(masterKey, lenMasterKey, seed, lenSeed, CID, GID)));

		return SUCCESS;
	}
	else {
		// Key in map, return error 
		return INSTANCE_EXISTS;
	}
}

int tearDownInstance(int instanceKey)
{
	if (instances.count(instanceKey) != 1)
	{
		return INSTANCE_NOT_FOUND;
	}

	instances.erase(instanceKey);

	return SUCCESS;
}

int CAPLEXPORT far CAPLPASCAL dll_InitInstance(int instanceKey,
	unsigned char masterKey[],
	int lenMasterKey,
	unsigned char seed[],
	int lenSeed,
	unsigned char CID,
	unsigned char GID)
{
	return initInstance(instanceKey, masterKey, lenMasterKey, seed, lenSeed, CID, GID);
}

int CAPLEXPORT far CAPLPASCAL dll_TearDownInstance(int instanceKey)
{
	return tearDownInstance(instanceKey);
}

int CAPLEXPORT far CAPLPASCAL dll_SetupInstance(int instanceKey)
{
	if (instances.count(instanceKey) != 1)
	{
		return INSTANCE_NOT_FOUND;
	}

	return instances[instanceKey]->protocolHandler->setup();
}

int CAPLEXPORT far CAPLPASCAL dll_GenerateKey(int instanceKey,
	unsigned char macTrunc[],
	int length,
	unsigned char timestamp)
{
	if (instances.count(instanceKey) != 1)
	{
		return INSTANCE_NOT_FOUND;
	}

	return instances[instanceKey]->protocolHandler->generateKey(timestamp,
		macTrunc, length);
}

int CAPLEXPORT far CAPLPASCAL dll_VerifyKey(int instanceKey,
	unsigned char macTrunc[],
	int length,
	unsigned char timestamp)
{
	if (instances.count(instanceKey) != 1)
	{
		return INSTANCE_NOT_FOUND;
	}

	return instances[instanceKey]->protocolHandler->verifySign(macTrunc,
		length, timestamp);
}

int CAPLEXPORT far CAPLPASCAL dll_MasterKeyLen()
{
	return MASTER_KEY_LEN;
}

int CAPLEXPORT far CAPLPASCAL dll_SeedLen()
{
	return SEED_LEN;
}
