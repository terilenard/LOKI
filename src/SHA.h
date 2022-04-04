#pragma once
#ifndef INCLUDE_SHA_H
#define INCLUDE_SHA_H
#include <cstdlib>
#include <windows.h>
#include <wincrypt.h>


class SHA
{

public:
	SHA();
	~SHA();

	int setup();
	int hash(unsigned char buff[], int length);
	void reset();

	PBYTE result();
	DWORD length();

protected:
	HCRYPTPROV	 hCryptProv = NULL;
	HCRYPTHASH  hashHandler = NULL;
	DWORD dwDataLen = 0;
	PBYTE pbHash = NULL;

};
#endif
