#pragma once
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <regex>

#ifndef RSALITE_H
#define RSALITE_H

class RSALite
{
public:
	static std::string createJWT(std::string header, std::string payload, std::string privateKey);
};


class BigInteger
{
public:
    static const int DB;
    static const int DM;
    static const int DV;
    static const int BI_FP;
    static const double FV;
    static const int F1;
    static const int F2;

    static BigInteger* nbi();
    static BigInteger* nbv(int i);

    std::vector<unsigned int> data;
    int t = 0;
    int s = 0;

    BigInteger();
    BigInteger(const std::string& a);
    ~BigInteger();

    void fromString(const std::string& s);
    void clamp();
    void fromInt(int x);
    int bitLength();
    BigInteger* mod(BigInteger& a);
    void divRemTo(BigInteger& m, BigInteger& r);
    void lShiftTo(int n, BigInteger& r);
    void dlShiftTo(int n, BigInteger& r);
    void subTo(BigInteger& a, BigInteger& r);
    void rShiftTo(int n, BigInteger& r);
    unsigned int am(int i, double x, BigInteger& w, int j, double c, int n);
    int invDigit();
    int compareTo(BigInteger& a);
    void copyTo(BigInteger& r);
    void drShiftTo(int n, BigInteger& r);
    void squareTo(BigInteger& r);
    void multiplyTo(BigInteger& a, BigInteger& r);
    BigInteger* modPow(BigInteger& e, BigInteger& m);
    BigInteger* add(BigInteger& a);
    void addTo(BigInteger& a, BigInteger& r);
    BigInteger* subtract(BigInteger& a);
    BigInteger* multiply(BigInteger& a);
    std::string toString();
    void print();
    unsigned int intValue();

private:
    std::map<int, int> BI_RC;
    const std::string BI_RM;

    void _init();
    int _intAt(const std::string& s, int i);
    int _nbits(unsigned int x);
};

class Digest {
public:
    static std::string digestStringWithSHA256(const std::string& data);
    static std::string getPaddedDigestInfoHex(std::string s, int keySize);
    static std::string urlsafeB64Encode(const std::string& value);
    static char int2char(int n);
    static std::string hex2b64(std::string h);
    static const std::string b64map;
    static const char b64pad;
    static std::string urlsafe(std::string s);

private:
    static const std::string base64_chars;
    static const std::string BI_RM;
    static std::vector<unsigned int> _convertStringToWordArray(std::string latin1Str);
    static std::string _convertWordArrayToString(std::vector<unsigned int> words, int sigBytes);
    static char _intToHex(unsigned int val);
    static void _process(std::vector<unsigned int>& H, std::vector<unsigned int>& K, std::vector<unsigned int>& W, std::vector<unsigned int>& dataWords, int dataSigBytes);
    static std::string _base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
    static std::vector<unsigned int> digestDataWords;
    static int digestDataSigBytes;
};

class Montgomery
{
public:
    BigInteger* m;
    int mp;
    int mpl;
    int mph;
    int um;
    int mt2;

    Montgomery(BigInteger* m);
    ~Montgomery();

    BigInteger* convert(BigInteger& x);
    BigInteger* revert(BigInteger& x);
    void reduce(BigInteger& x);
    void sqrTo(BigInteger& x, BigInteger& r);
    void mulTo(BigInteger& x, BigInteger& y, BigInteger& r);
};

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
    std::string _getCleanB64(std::string str);
};

#endif