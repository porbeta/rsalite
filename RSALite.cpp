#include <string>
#include <iostream>
#include <regex>
#include "Digest.h"
#include "BigInteger.h"
#include "RSAKey.h"
#include "RSALite.h"

std::string RSALite::createJWT(std::string header, std::string payload, std::string privateKey) {
    std::string signingInput = Digest::urlsafeB64Encode(header) + "." + Digest::urlsafeB64Encode(payload);
    std::string sHashHex = Digest::digestStringWithSHA256(signingInput);

    RSAKey* rsaKey = new RSAKey(privateKey);

    std::string hPM = Digest::getPaddedDigestInfoHex(sHashHex, rsaKey->n->bitLength());

    BigInteger* biPaddedMessage = new BigInteger(hPM);

    BigInteger* xpMod = biPaddedMessage->mod(*rsaKey->p);
    BigInteger* xp = xpMod->modPow(*rsaKey->dmp1, *rsaKey->p);
    delete(xpMod);

    BigInteger* xqMod = biPaddedMessage->mod(*rsaKey->q);
    BigInteger* xq = xqMod->modPow(*rsaKey->dmq1, *rsaKey->q);
    delete(xqMod);

    while (xp->compareTo(*xq) < 0) {
        BigInteger* newXP = xp->add(*rsaKey->p);
        delete(xp);
        xp = newXP;
    }

    BigInteger* biSignSub = xp->subtract(*xq);
    BigInteger* biSignMult1 = biSignSub->multiply(*rsaKey->coeff);
    delete(biSignSub);
    BigInteger* biSignMod = biSignMult1->mod(*rsaKey->p);
    delete(biSignMult1);
    BigInteger* biSignMult2 = biSignMod->multiply(*rsaKey->q);
    delete(biSignMod);
    BigInteger* biSign = biSignMult2->add(*xq);
    delete(biSignMult2);

    std::string hexSign = biSign->toString();
    delete(biSign);

    std::string s = "";
    int nZero = rsaKey->n->bitLength() / 4 - hexSign.length();

    for (int i = 0; i < nZero; i++) {
        s = s + "0";
    }

    std::string hSig = s + hexSign;
    std::string hSign = Digest::urlsafe(Digest::hex2b64(hSig));

    delete(xq);
    delete(xp);
    delete(biPaddedMessage);
    delete(rsaKey);

    std::string token = signingInput + "." + hSign;
    char* ret = new char[token.length() + 1];
    strcpy_s(ret, token.length() + 1, token.c_str());

    return ret;
}