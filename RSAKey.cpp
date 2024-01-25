#include "RSAKey.h"
#include "BigInteger.h"
#include "Digest.h"
#include <string>
#include <regex>
#include <stdexcept>
#include <iostream>

BigInteger* n;
int e;
BigInteger* d;
BigInteger* p;
BigInteger* q;
BigInteger* dmp1;
BigInteger* dmq1;
BigInteger* coeff;

RSAKey::RSAKey(std::string& prvKeyPEM) {
    std::string prvKeyHex = this->_pemtohex(prvKeyPEM, "PRIVATE KEY");
    this->_readPKCS8PrvKeyHex(prvKeyHex);
}

RSAKey::~RSAKey() {
    delete(this->n);
    delete(this->d);
    delete(this->p);
    delete(this->q);
    delete(this->dmp1);
    delete(this->dmq1);
    delete(this->coeff);
}

void RSAKey::_readPKCS8PrvKeyHex(std::string h) {
    std::string hN, hE, hD, hP, hQ, hDP, hDQ, hCO;

    if (this->_isASN1HEX(h) == false) {
        throw std::invalid_argument("not ASN.1 hex string");
    }

    std::vector<int> hNNthList{ 2, 0, 1 };
    std::vector<int> hENthList{ 2, 0, 2 };
    std::vector<int> hDNthList{ 2, 0, 3 };
    std::vector<int> hPNthList{ 2, 0, 4 };
    std::vector<int> hQNthList{ 2, 0, 5 };
    std::vector<int> hDPNthList{ 2, 0, 6 };
    std::vector<int> hDQNthList{ 2, 0, 7 };
    std::vector<int> hCONthList{ 2, 0, 8 };

    try {
        hN = this->_getVbyListEx(h, 0, hNNthList, "02");
        hE = this->_getVbyListEx(h, 0, hENthList, "02");
        hD = this->_getVbyListEx(h, 0, hDNthList, "02");
        hP = this->_getVbyListEx(h, 0, hPNthList, "02");
        hQ = this->_getVbyListEx(h, 0, hQNthList, "02");
        hDP = this->_getVbyListEx(h, 0, hDPNthList, "02");
        hDQ = this->_getVbyListEx(h, 0, hDQNthList, "02");
        hCO = this->_getVbyListEx(h, 0, hCONthList, "02");
    }
    catch (std::exception()) {
        throw std::invalid_argument("malformed PKCS#8 plain RSA private key");
    }

    this->_setPrivateEx(hN, hE, hD, hP, hQ, hDP, hDQ, hCO);
}

std::string RSAKey::_pemtohex(std::string s, std::string sHead) {
    if (s.find("-----BEGIN ") == -1)
        throw std::invalid_argument("can't find PEM header");

    if (sHead.empty()) {
        throw std::invalid_argument("sHead cannot be null");
    }

    std::regex e1("^[^]*-----BEGIN " + sHead + "-----");
    std::regex e2("-----END " + sHead + "-----[^]*$");

    s = std::regex_replace(s, e1, "");
    s = std::regex_replace(s, e2, "");

    return this->_b64nltohex(s);
}

std::string RSAKey::_b64nltohex(std::string s) {
    std::regex e("/[^0-9A-Za-z/+=]*/ g");
    std::string b64 = std::regex_replace(s, e, "");
    std::string hex = this->_b64tohex(b64);
    return hex;
}

std::string RSAKey::_b64tohex(std::string s) {
    std::string ret = "";
    int i;
    int k = 0; // b64 state, 0-3
    int slop;
    int v;

    for (i = 0; i < s.size(); ++i) {
        if (s[i] == Digest::b64pad) break;
        v = Digest::b64map.find(s.substr(i, 1));
        if (v < 0) continue;
        if (k == 0) {
            ret += Digest::int2char(v >> 2);
            slop = v & 3;
            k = 1;
        }
        else if (k == 1) {
            ret += Digest::int2char((slop << 2) | (v >> 4));
            slop = v & 0xf;
            k = 2;
        }
        else if (k == 2) {
            ret += Digest::int2char(slop);
            ret += Digest::int2char(v >> 2);
            slop = v & 3;
            k = 3;
        }
        else {
            ret += Digest::int2char((slop << 2) | (v >> 4));
            ret += Digest::int2char(v & 0xf);
            k = 0;
        }
    }
    if (k == 1)
        ret += Digest::int2char(slop << 2);
    return ret;
}



bool RSAKey::_isASN1HEX(std::string hex) {
    if (hex.size() % 2 == 1) return false;

    int  intL = this->_getVblen(hex, 0);
    std::string hT = hex.substr(0, 2);
    std::string hL = this->_getL(hex, 0);
    size_t hVLength = hex.size() - hT.size() - hL.size();
    if (hVLength == intL * 2) return true;

    return false;
};

int RSAKey::_getVblen(std::string s, int idx) {
    std::string hLen;
    BigInteger* bi;

    hLen = this->_getL(s, idx);
    if (hLen.empty()) return -1;
    if (hLen.substr(0, 1) == "8") {
        bi = new BigInteger(hLen.substr(2));
    }
    else {
        bi = new BigInteger(hLen);
    }

    int ret = bi->intValue();
    delete(bi);

    return ret;
}

std::string RSAKey::_getL(std::string s, int idx) {
    int len = this->_getLblen(s, idx);
    if (len < 1) return "";
    return s.substr(idx + 2, len * 2);
};

int RSAKey::_getLblen(std::string s, int idx) {
    if (s[idx + 2] != '8') return 1;
    int i = s[idx + 3] - '0';
    if (i == 0) return -1;             // length octet '80' indefinite length
    if (0 < i && i < 10) return i + 1; // including '8?' octet;
    return -2;                         // malformed format
};

std::string RSAKey::_getVbyListEx(std::string h, int currentIndex, std::vector<int>& nthList, std::string checkingTag) {
    int idx;
    std::string v;

    idx = this->_getIdxbyListEx(h, currentIndex, nthList, checkingTag);
    v = this->_getV(h, idx);

    return v;
}

int RSAKey::_getIdxbyListEx(std::string h, int currentIndex, std::vector<int>& nthList, std::string checkingTag) {
    int firstNth = 0;
    std::vector<int> a;

    if (nthList.size() == 0) {
        if (h.substr(currentIndex, 2).compare(checkingTag) != 0) {
            return -1;
        }

        return currentIndex;
    } else if(nthList.size() > 0) {
        firstNth = nthList[0];
        nthList.erase(nthList.begin());
    }

    a = this->_getChildIdx(h, currentIndex);

    int count = 0;
    for (int i = 0; i < a.size(); i++) {
        if (count == firstNth) {
            return this->_getIdxbyListEx(h, a[i], nthList, checkingTag);
        }

        count++;
    }
    return -1;
};

std::string RSAKey::_getV(std::string s, int idx) {
    int idx1 = this->_getVidx(s, idx);
    int blen = this->_getVblen(s, idx);
    return s.substr(idx1, blen * 2);
};

int RSAKey::_getVidx(std::string s, int idx) {
    int l_len = this->_getLblen(s, idx);
    if (l_len < 0) return l_len;
    return idx + (l_len + 1) * 2;
};

std::vector<int> RSAKey::_getChildIdx(std::string h, int idx) {
    std::vector<int> a;
    int idxStart, totalChildBlen, currentChildBlen;

    idxStart = this->_getVidx(h, idx);
    totalChildBlen = this->_getVblen(h, idx) * 2;

    if (h.substr(idx, 2) == "03") {  // BITSTRING without unusedbits
        idxStart += 2;
        totalChildBlen -= 2;
    }

    currentChildBlen = 0;
    int i = idxStart;

    while (currentChildBlen <= totalChildBlen) {
        int tlvBlen = this->_getTLVblen(h, i);
        currentChildBlen += tlvBlen;

        if (currentChildBlen <= totalChildBlen) a.push_back(i);

        i += tlvBlen;

        if (currentChildBlen >= totalChildBlen) break;
    }
    return a;
};

int RSAKey::_getTLVblen(std::string h, int idx) {
    return 2 + this->_getLblen(h, idx) * 2 + this->_getVblen(h, idx) * 2;
};

void RSAKey::_setPrivateEx(std::string N, std::string E, std::string D, std::string P, std::string Q, std::string DP, std::string DQ, std::string C) {
    if (N.empty()) throw new std::invalid_argument("RSASetPrivateEx N.length == 0");
    if (E.empty()) throw new std::invalid_argument("RSASetPrivateEx E.length == 0");

    if (N.size() > 0 && E.size() > 0) {
        this->n = new BigInteger(N);
        this->e = std::stoi(E, nullptr, 16);
        this->d = new BigInteger(D);
        this->p = new BigInteger(P);
        this->q = new BigInteger(Q);
        this->dmp1 = new BigInteger(DP);
        this->dmq1 = new BigInteger(DQ);
        this->coeff = new BigInteger(C);
    }
    else {
        throw new std::invalid_argument("Invalid RSA private key in RSASetPrivateEx");
    }
}
