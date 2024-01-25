#pragma once
#include <string>
#include <vector>
#include "BigInteger.h"

#ifndef RSAKEY_H
#define RSAKEY_H

class RSAKey
{
public:
	BigInteger* n;
	int e;
	BigInteger* d;
	BigInteger* p;
	BigInteger* q;
	BigInteger* dmp1;
	BigInteger* dmq1;
	BigInteger* coeff;

	RSAKey(std::string& prvKeyPEM);
	~RSAKey();

private:
	void _readPKCS8PrvKeyHex(std::string h);
	std::string _pemtohex(std::string s, std::string sHead);
	std::string _b64nltohex(std::string s);
	std::string _b64tohex(std::string s);
	bool _isASN1HEX(std::string hex);
	int _getVblen(std::string s, int idx);
	std::string _getL(std::string s, int idx);
	int _getLblen(std::string s, int idx);
	std::string _getVbyListEx(std::string h, int currentIndex, std::vector<int>& nthList, std::string checkingTag);
	int _getIdxbyListEx(std::string h, int currentIndex, std::vector<int>& nthList, std::string checkingTag);
	std::string _getV(std::string s, int idx);
	int _getVidx(std::string s, int idx);
	std::vector<int> _getChildIdx(std::string h, int idx);
	int _getTLVblen(std::string h, int idx);
	void _setPrivateEx(std::string N, std::string E, std::string D, std::string P, std::string Q, std::string DP, std::string DQ, std::string C);
};

#endif