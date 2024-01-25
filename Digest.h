#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <regex>

#ifndef DIGEST_H
#define DIGEST_H

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
    static std::vector<uint32_t> _convertStringToWordArray(std::string latin1Str);
    static std::string _convertWordArrayToString(std::vector<uint32_t> words, int sigBytes);
    static char _intToHex(uint32_t val);
    static void _process(std::vector<uint32_t>& H, std::vector<uint32_t>& K, std::vector<uint32_t>& W, std::vector<uint32_t>& dataWords, int dataSigBytes);
    static std::string _base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
};

#endif