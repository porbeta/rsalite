#include "Digest.h"
#include <cmath>
#include <vector>
#include <iostream>
#include <string>
#include <cstdint>

std::vector<unsigned int> Digest::_convertStringToWordArray(std::string latin1Str) {
    unsigned int latin1StrLength = latin1Str.length();
    std::vector<unsigned int> words(latin1StrLength / 4, 0);
    for (unsigned int i = 0; i < latin1StrLength; i++) {
        words[i >> 2] |= (latin1Str[i] & 0xff) << (24 - (i % 4) * 8);
    }
    return words;
}

std::string Digest::_convertWordArrayToString(std::vector<unsigned int> words, int sigBytes) {
    std::string hexChars;
    for (unsigned int i = 0; i < sigBytes; i++) {
        unsigned int bite = (words[i >> 2] >> (24 - (i % 4) * 8)) & 0xff;
        hexChars.push_back(_intToHex(bite >> 4));
        hexChars.push_back(_intToHex(bite & 0x0f));
    }
    return hexChars;
}

char Digest::_intToHex(unsigned int val) {
    if (val < 0 || val > 15) {
        throw std::invalid_argument("number does not correspond to hex value");
    }

    if (val > 9) {
        if (val % 10 == 0) {
            return 'a';
        }
        else if (val % 10 == 1) {
            return 'b';
        }
        else if (val % 10 == 2) {
            return 'c';
        }
        else if (val % 10 == 3) {
            return 'd';
        }
        else if (val % 10 == 4) {
            return 'e';
        }
        else if (val % 10 == 5) {
            return 'f';
        }
    }

    return val + '0';
}

void Digest::_process(std::vector<unsigned int>& H, std::vector<unsigned int>& K, std::vector<unsigned int>& W, std::vector<unsigned int>& dataWords, int dataSigBytes) {
    int blockSize = 16;
    int blockSizeBytes = blockSize * 4;
    // Count blocks ready
    int nBlocksReady = dataSigBytes / blockSizeBytes;
    nBlocksReady = std::max((int)nBlocksReady, 0);
    // Count words ready
    int nWordsReady = nBlocksReady * blockSize;
    // Count bytes ready
    int nBytesReady = std::min(nWordsReady * 4, dataSigBytes);
    // Process blocks
    if (nWordsReady) {
        for (int offset = 0; offset < nWordsReady; offset += blockSize) {
            // Perform concrete-algorithm logic
            // Working variables
            unsigned int a = H[0];
            unsigned int b = H[1];
            unsigned int c = H[2];
            unsigned int d = H[3];
            unsigned int e = H[4];
            unsigned int f = H[5];
            unsigned int g = H[6];
            unsigned int h = H[7];
            // Computation
            for (int i = 0; i < 64; i++) {
                if (i < 16) {
                    W[i] = dataWords[offset + i] | 0;
                }
                else {
                    unsigned int gamma0x = W[i - 15];
                    unsigned int gamma0 = ((gamma0x << 25) | (gamma0x >> 7)) ^
                        ((gamma0x << 14) | (gamma0x >> 18)) ^
                        (gamma0x >> 3);
                    unsigned int gamma1x = W[i - 2];
                    unsigned int gamma1 = ((gamma1x << 15) | (gamma1x >> 17)) ^
                        ((gamma1x << 13) | (gamma1x >> 19)) ^
                        (gamma1x >> 10);
                    W[i] = gamma0 + gamma1 + W[i - 16] + W[i - 7];
                }
            }
            // More computation
            unsigned int temp1, temp2, ch, maj, sigma0, sigma1;
            for (int i = 0; i < 64; i++) {
                sigma1 = ((e << 26) | (e >> 6)) ^ ((e << 21) | (e >> 11)) ^ ((e << 7) | (e >> 25));
                ch = (e & f) ^ (~e & g);
                temp1 = h + sigma1 + ch + K[i] + W[i];
                sigma0 = ((a << 30) | (a >> 2)) ^ ((a << 19) | (a >> 13)) ^ ((a << 10) | (a >> 22));
                maj = (a & b) ^ (a & c) ^ (b & c);
                temp2 = sigma0 + maj;
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }
            // Update hash values
            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        }
    }
}

std::string Digest::digestStringWithSHA256(const std::string& data) {
    std::vector<unsigned int> H{ 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225 };
    std::vector<unsigned int> K{ 1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080,  310598401,  607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774,  264347078,  604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711,  113926993,  338241895, 666307205,  773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909,  275423344, 430227734,  506948616,  659060556,  883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298 };
    std::vector<unsigned int> W(64, 0);

    size_t sigBytes = H.size() * 4;

    // Start _append
    std::vector<unsigned int> dataWords = _convertStringToWordArray(data);
    size_t dataSigBytes = dataWords.size() * 4;

    size_t initialLength = (sigBytes >> 2) + 1;
    size_t oldDataSigBytes = 0;
    std::vector<unsigned int> oldDataWords(initialLength, oldDataSigBytes);

    // Clamp
    oldDataWords[sigBytes >> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
    oldDataWords.resize((sigBytes + 3) / 4);

    // Concat
    for (size_t i = 0; i < oldDataSigBytes; i++) {
        unsigned int dataByte = (dataWords[i >> 2] >> (24 - (i % 4) * 8)) & 0xff;
        oldDataWords[(sigBytes + i) >> 2] |= dataByte << (24 - ((sigBytes + i) % 4) * 8);
    }

    size_t nDataBytes = dataSigBytes;

    // End _append

    std::vector<unsigned int> dW1 = std::vector<unsigned int>(dataWords.begin(), dataWords.end());

    _process(H, K, W, dW1, dataSigBytes);

    dataWords.clear();
    dataSigBytes = 0;

    size_t nBitsTotal = nDataBytes * 8;
    size_t nBitsLeft = dataSigBytes * 8;

    // Add padding
    std::vector<unsigned int> dW2((((nBitsLeft + 64) >> 9) << 4 | 15) + 1, 0);

    dW2[nBitsLeft >> 5] |= 0x80 << (24 - nBitsLeft % 32);
    dW2[((nBitsLeft + 64) >> 9) << 4 | 14] = static_cast<unsigned int>(nBitsTotal / 0x100000000);
    dW2[((nBitsLeft + 64) >> 9) << 4 | 15] = static_cast<unsigned int>(nBitsTotal);
    dataSigBytes = dW2.size() * 4;

    // Hash final blocks
    _process(H, K, W, dW2, dataSigBytes);

    // Return final computed hash
    // Convert to String from WordArray
    return _convertWordArrayToString(H, sigBytes);
}

std::string Digest::getPaddedDigestInfoHex(std::string s, int keySize) {
    std::string hDigestInfo = "3031300d060960864801650304020105000420" + s;
    int pmStrLen = keySize / 4; // minimum PM length

    std::string hHead = "0001";
    std::string hTail = "00" + hDigestInfo;
    std::string hMid = "";
    int fLen = pmStrLen - hHead.length() - hTail.length();

    for (int i = 0; i < fLen; i += 2) {
        hMid += "ff";
    }

    return hHead + hMid + hTail;
}

std::string Digest::_base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string Digest::urlsafeB64Encode(const std::string& value) {
    std::string base64_encoded = _base64_encode(reinterpret_cast<const unsigned char*>(value.c_str()), value.length());
    
    return urlsafe(base64_encoded);
}

char Digest::int2char(int n) {
    return BI_RM[n];
}

std::string Digest::hex2b64(std::string h) {
    int i;
    unsigned int c;
    std::string ret = "";

    for (i = 0; i + 3 <= h.length(); i += 3) {
        std::string str = h.substr(i, 3);
        c = std::stoi(str, nullptr, 16);
        int fi = c >> 6;
        int si = c & 63;

        ret.append(1, Digest::b64map[fi]);
        ret.append(1, Digest::b64map[si]);
    }

    if (i + 1 == h.length()) {
        c = std::stoi(h.substr(i, 1), nullptr, 16);
        int fi = c << 2;

        ret.append(1, Digest::b64map[fi]);
    }
    else if (i + 2 == h.length()) {
        c = std::stoi(h.substr(i, 2), nullptr, 16);
        int fi = c >> 2;
        int si = (c & 3) << 4;

        ret.append(1, Digest::b64map[fi]);
        ret.append(1, Digest::b64map[si]);
    }
    
    while ((ret.length() & 3) > 0) ret.append(1, Digest::b64pad);
   
    return ret;
}

std::string Digest::urlsafe(std::string s) {
    std::string::size_type pos;

    while ((pos = s.find('+')) != std::string::npos)
        s.replace(pos, 1, "-");
    while ((pos = s.find('/')) != std::string::npos)
        s.replace(pos, 1, "_");
    while ((pos = s.find('=')) != std::string::npos)
        s.erase(pos, 1);

    return s;
}

const std::string Digest::base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

const std::string Digest::BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";

const std::string Digest::b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const char Digest::b64pad = '=';