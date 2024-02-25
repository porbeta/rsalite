#include "RSALite.h"
#include <string>
#include <iostream>
#include <cmath>
#include <vector>
#include <map>
#include <cstdint>
#include <stdexcept>

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

    return signingInput + "." + hSign;
}

const int BigInteger::DB = 26;
const int BigInteger::DM = (1 << DB) - 1;
const int BigInteger::DV = (1 << DB);
const int BigInteger::BI_FP = 52;
const double BigInteger::FV = std::pow(2, BigInteger::BI_FP);
const int BigInteger::F1 = BI_FP - DB;
const int BigInteger::F2 = 2 * DB - BI_FP;

std::vector<unsigned int> data;
int t = 0;
int s = 0;

std::map<int, int>  BI_RC;
const std::string BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";

BigInteger::BigInteger() {
    this->_init();
}

BigInteger::BigInteger(const std::string& a) {
    this->_init();

    if (!a.empty()) {
        this->fromString(a);
    }
}

BigInteger::~BigInteger() {}

// Static method to create a new, unset BigInteger
BigInteger* BigInteger::nbi() {
    return new BigInteger();
}

// Static method to create a BigInteger with a given integer value
BigInteger* BigInteger::nbv(int i) {
    BigInteger* r = new BigInteger();
    r->fromInt(i);
    return r;
}

void BigInteger::fromString(const std::string& str) {
    int k = 4;
    this->t = 0;
    this->s = 0;

    int i = int(str.length()) - 1;
    int mi = false, sh = 0;

    while (i >= 0) {
        int x = this->_intAt(str, i);

        if (sh == 0) {
            this->t++;
            this->data.resize(this->t);
            this->data[this->t - 1] = x; // Assuming data is the internal storage
        }
        else if (sh + k > this->DB) {
            this->data[this->t - 1] |= (x & ((1 << (this->DB - sh)) - 1)) << sh;
            this->t++;
            this->data.resize(this->t);
            this->data[this->t - 1] = (x >> (this->DB - sh));
        }
        else {
            this->data[this->t - 1] |= x << sh;
        }

        sh += k;

        if (sh >= this->DB) sh -= this->DB;

        i--;
    }

    this->clamp();
}

// (protected) clamp off excess high words
void BigInteger::clamp() {
    int c = this->s & DM;
    while (t > 0 && this->data[t - 1] == c) --t;
}

void BigInteger::fromInt(int x) {
    this->t = 1;
    this->s = 0;

    data.resize(this->t);

    if (x > 0) this->data[0] = x;
    else if (x < -1) this->data[0] = x + this->DV;
    else this->t = 0;
}

unsigned int BigInteger::intValue() {
    if (this->s < 0) {
        if (this->t == 1) return this->data[0] - this->DV;
        else if (this->t == 0) return -1;
    }
    else if (this->t == 1) return this->data[0];
    else if (this->t == 0) return 0;
    // assumes 16 < DB < 32
    return ((this->data[1] & ((1 << (32 - this->DB)) - 1)) << this->DB) | this->data[0];
}

int BigInteger::bitLength() {
    if (this->t <= 0) return 0;
    return this->DB * (this->t - 1) + this->_nbits(this->data[this->t - 1] ^ (this->s & this->DM));
}

BigInteger* BigInteger::mod(BigInteger& a) {
    BigInteger* r = nbi();
    this->divRemTo(a, *r);

    return r;
}

void BigInteger::divRemTo(BigInteger& m, BigInteger& r) {
    BigInteger* y = nbi();
    int ts = this->s;

    int nsh = this->DB - this->_nbits(m.data[m.t - 1]);	// normalize modulus

    m.lShiftTo(nsh, *y);
    this->lShiftTo(nsh, r);

    int ys = y->t;
    double y0 = y->data[ys - 1];
    double yt = y0 * (1 << this->F1) + (y->data[ys - 2] >> this->F2);
    double d1 = this->FV / yt, d2 = (1 << this->F1) / yt, e = 1 << this->F2;
    int i = r.t, j = i - ys;

    BigInteger* t = nbi();

    y->dlShiftTo(j, *t);

    BigInteger* one = BigInteger::nbv(1);
    one->dlShiftTo(ys, *t);

    t->subTo(*y, *y);	// "negative" y so we can replace sub with am later

    while (--j >= 0) {
        // Estimate quotient digit
        --i;
        double qd = std::floor((double)r.data[i] * d1 + ((double)r.data[i - 1] + e) * d2);
        r.data[i] += y->am(0, qd, r, j, 0, ys);
    }

    r.t = ys;
    r.clamp();
    r.rShiftTo(nsh, r);	// Denormalize remainder

    delete(y);
    delete(t);
    delete(one);
}

void BigInteger::lShiftTo(int n, BigInteger& r) {
    int bs = n % this->DB;
    int cbs = this->DB - bs;
    int bm = (1 << cbs) - 1;
    int ds = std::floor(n / this->DB), c = (this->s << bs) & this->DM, i;

    r.data.resize(this->t + 1);

    for (i = this->t - 1; i >= 0; --i) {
        r.data[i + ds + 1] = (this->data[i] >> cbs) | c;
        c = (this->data[i] & bm) << bs;
    }

    for (i = ds - 1; i >= 0; --i) r.data[i] = 0;
    r.data[ds] = c;
    r.t = this->t + ds + 1;
    r.s = this->s;
    r.clamp();
}

void BigInteger::dlShiftTo(int n, BigInteger& r) {
    int i;

    r.data.resize(this->t + n);

    for (i = this->t - 1; i >= 0; --i) r.data[i + n] = this->data[i];
    for (i = n - 1; i >= 0; --i) r.data[i] = 0;
    r.t = this->t + n;
    r.s = this->s;
}

void BigInteger::subTo(BigInteger& a, BigInteger& r) {
    int i = 0, c = 0, m = std::min(a.t, this->t);

    r.data.resize(m);

    while (i < m) {
        c += this->data[i] - a.data[i];
        r.data[i++] = c & this->DM;
        c >>= this->DB;
    }
    if (a.t < this->t) {
        c -= a.s;

        r.data.resize(this->t);

        while (i < this->t) {
            c += this->data[i];
            r.data[i++] = c & this->DM;
            c >>= this->DB;
        }
        c += this->s;
    }
    else {
        c += this->s;
        while (i < a.t) {
            c -= a.data[i];
            r.data[i++] = c & this->DM;
            c >>= this->DB;
        }
        c -= a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c < -1) r.data[i++] = this->DV + c;
    else if (c > 0) r.data[i++] = c;
    r.t = i;
    r.clamp();
}


void BigInteger::rShiftTo(int n, BigInteger& r) {
    r.s = this->s;
    int ds = std::floor(n / this->DB);

    if (ds >= this->t) { r.t = 0; return; }
    int bs = n % this->DB;
    int cbs = this->DB - bs;
    int bm = (1 << bs) - 1;

    r.data[0] = this->data[ds] >> bs;

    for (int i = ds + 1; i < this->t; ++i) {
        r.data[i - ds - 1] |= (this->data[i] & bm) << cbs;
        r.data[i - ds] = this->data[i] >> bs;
    }
    if (bs > 0) r.data[this->t - ds - 1] |= (this->s & bm) << cbs;
    r.t = this->t - ds;
    r.clamp();
}

unsigned int BigInteger::am(int i, double x, BigInteger& w, int j, double c, int n) {
    while (--n >= 0) {
        long long v = x * this->data[i++] + w.data[j] + c;
        c = std::floor(v / 0x4000000);
        w.data[j++] = v & 0x3ffffff;
    }
    return c;
}

int BigInteger::invDigit() {
    if (this->t < 1) return 0;
    int x = this->data[0];
    if ((x & 1) == 0) return 0;
    int y = x & 3;		// y == 1/x mod 2^2

    y = (y * (2 - (x & 0xf) * y)) & 0xf;	// y == 1/x mod 2^4
    y = (y * (2 - (x & 0xff) * y)) & 0xff;	// y == 1/x mod 2^8
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;	// y == 1/x mod 2^16
    // last step - calculate inverse mod DV directly;
    // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
    y = (y * (2 - x * y % this->DV)) % this->DV;		// y == 1/x mod 2^dbits
    // we really want the negative inverse, and -DV < y < DV
    return (y > 0) ? this->DV - y : -y;
}

int BigInteger::compareTo(BigInteger& a) {
    int r = this->s - a.s;
    if (r != 0) return r;
    int i = this->t;
    r = i - a.t;
    if (r != 0) return (this->s < 0) ? -r : r;
    while (--i >= 0) if ((r = this->data[i] - a.data[i]) != 0) return r;
    return 0;
}

void BigInteger::copyTo(BigInteger& r) {
    r.data.resize(this->t);

    for (int i = this->t - 1; i >= 0; --i) r.data[i] = this->data[i];
    r.t = this->t;
    r.s = this->s;
}

void BigInteger::drShiftTo(int n, BigInteger& r) {
    for (int i = n; i < this->t; ++i) r.data[i - n] = this->data[i];
    r.t = std::max(this->t - n, 0);
    r.s = this->s;
}

void BigInteger::squareTo(BigInteger& r) {
    int i = r.t = 2 * this->t;
    r.data.resize(i);

    while (--i >= 0) r.data[i] = 0;

    for (i = 0; i < this->t - 1; ++i) {
        unsigned int c = this->am(i, this->data[i], r, 2 * i, 0, 1);
        if ((r.data[i + this->t] += this->am(i + 1, 2 * this->data[i], r, 2 * i + 1, c, this->t - i - 1)) >= this->DV) {
            r.data[i + this->t] -= this->DV;
            r.data[i + this->t + 1] = 1;
        }
    }

    if (r.t > 0) r.data[r.t - 1] += this->am(i, (long long)this->data[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
}

void BigInteger::multiplyTo(BigInteger& a, BigInteger& r) {
    int i = this->t;
    r.t = i + a.t;

    r.data.resize(r.t);
    while (--i >= 0) r.data[i] = 0;
    for (i = 0; i < a.t; ++i) r.data[i + this->t] = this->am(0, a.data[i], r, i, 0, this->t);
    r.s = 0;
    r.clamp();

    BigInteger* zero = BigInteger::nbv(0);

    if (this->s != a.s) zero->subTo(r, r);

    delete(zero);
}

BigInteger* BigInteger::modPow(BigInteger& e, BigInteger& m) {
    int i = e.bitLength(), k;

    BigInteger* r = nbv(1);

    if (i <= 0) return r;
    else if (i < 18) k = 1;
    else if (i < 48) k = 3;
    else if (i < 144) k = 4;
    else if (i < 768) k = 5;
    else k = 6;

    Montgomery* z = new Montgomery(&m);

    // precomputation
    int n = 3, k1 = k - 1, km = (1 << k) - 1, vs = (1 << k);
    std::vector<BigInteger*> g(vs, NULL);

    g[1] = z->convert(*this);

    if (k > 1) {
        BigInteger* g2 = nbi();
        z->sqrTo(*g[1], *g2);
        while (n <= km) {
            g[n] = nbi();
            z->mulTo(*g2, *g[n - 2], *g[n]);
            n += 2;
        }

        delete(g2);
    }

    int j = e.t - 1, w;
    bool is1 = true;
    BigInteger* r2 = nbi(), * t;

    i = this->_nbits(e.data[j]) - 1;

    while (j >= 0) {
        if (i >= k1) w = (e.data[j] >> (i - k1)) & km;
        else {
            w = (e.data[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
            if (j > 0) w |= e.data[j - 1] >> (this->DB + i - k1);
        }

        n = k;
        while ((w & 1) == 0) { w >>= 1; --n; }
        if ((i -= n) < 0) { i += this->DB; --j; }
        if (is1) {	// ret == 1, don't bother squaring or multiplying it
            g[w]->copyTo(*r);
            is1 = false;
        }
        else {
            while (n > 1) { z->sqrTo(*r, *r2); z->sqrTo(*r2, *r); n -= 2; }
            if (n > 0) {
                z->sqrTo(*r, *r2);
            }
            else {
                t = r;
                r = r2;
                r2 = t;
            }

            z->mulTo(*r2, *g[w], *r);
        }

        while (j >= 0 && (e.data[j] & (1 << i)) == 0) {
            z->sqrTo(*r, *r2);
            t = r;
            r = r2;
            r2 = t;

            if (--i < 0) { i = this->DB - 1; --j; }
        }
    }

    BigInteger* ret = z->revert(*r);

    delete(r2);

    for (int index = 0; index < g.size(); index++) {
        delete(g[index]);
    }
    g.clear();

    delete(z);
    delete(r);

    return ret;
}

BigInteger* BigInteger::add(BigInteger& a) {
    BigInteger* r = nbi();
    this->addTo(a, *r);
    return r;
}

void BigInteger::addTo(BigInteger& a, BigInteger& r) {
    int i = 0, m = std::min(a.t, this->t), c = 0;

    r.data.resize(m);

    while (i < m) {
        c += this->data[i] + a.data[i];
        r.data[i++] = c & this->DM;
        c >>= this->DB;
    }
    if (a.t < this->t) {
        c += a.s;

        r.data.resize(this->t);

        while (i < this->t) {
            c += this->data[i];
            r.data[i++] = c & this->DM;
            c >>= this->DB;
        }
        c += this->s;
    }
    else {
        c += this->s;

        r.data.resize(a.t);

        while (i < a.t) {
            c += a.data[i];
            r.data[i++] = c & this->DM;
            c >>= this->DB;
        }
        c += a.s;
    }
    r.s = (c < 0) ? -1 : 0;

    if (c > 0) {
        r.data[i++] = c;
    }
    else if (c < -1) {
        r.data[i++] = this->DV + c;
    }

    r.t = i;
    r.clamp();
}

BigInteger* BigInteger::subtract(BigInteger& a) {
    BigInteger* r = nbi();
    this->subTo(a, *r);
    return r;
}

BigInteger* BigInteger::multiply(BigInteger& a) {
    BigInteger* r = nbi();
    this->multiplyTo(a, *r);
    return r;
}

std::string BigInteger::toString() {
    int k = 4, km = (1 << k) - 1, d, i = this->t;
    bool m = false;
    std::string r = "";

    int p = this->DB - (i * this->DB) % k;

    if (i-- > 0) {
        if (p < this->DB && (d = this->data[i] >> p) > 0) { m = true; r = Digest::int2char(d); }
        while (i >= 0) {
            if (p < k) {
                d = (this->data[i] & ((1 << p) - 1)) << (k - p);
                d |= this->data[--i] >> (p += this->DB - k);
            }
            else {
                d = (this->data[i] >> (p -= k)) & km;
                if (p <= 0) { p += this->DB; --i; }
            }
            if (d > 0) m = true;
            if (m) r += Digest::int2char(d);
        }
    }
    return m ? r : "0";
}

void BigInteger::print() {
    std::cout << "BigInteger {" << std::endl;
    int lastIndex = this->data.size() - 1;

    for (int i = 0; i < lastIndex; i++) {
        std::cout << "\t'" << i << "': " << this->data[i] << "," << std::endl;
    }

    if (lastIndex > 0) {
        std::cout << "\t'" << lastIndex << "': " << this->data[lastIndex] << std::endl;
    }

    std::cout << "  t: " << this->t << std::endl;
    std::cout << "  s: " << this->s << std::endl;
    std::cout << "}" << std::endl;
}

void BigInteger::_init() {
    int rr, vv;
    this->BI_RC.clear();

    rr = int("0"[0]);
    for (vv = 0; vv <= 9; ++vv) this->BI_RC[rr++] = vv;
    rr = int("a"[0]);
    for (vv = 10; vv < 36; ++vv) this->BI_RC[rr++] = vv;
    rr = int("A"[0]);
    for (vv = 10; vv < 36; ++vv) this->BI_RC[rr++] = vv;
}

int BigInteger::_intAt(const std::string& s, int i) {
    std::map<int, int>::iterator it = this->BI_RC.find(int(s[i]));

    if (it != this->BI_RC.end()) {
        return it->second;
    }

    return -1;
}

int BigInteger::_nbits(unsigned int x) {
    int r = 1, t;
    if ((t = x >> 16) != 0) { x = t; r += 16; }
    if ((t = x >> 8) != 0) { x = t; r += 8; }
    if ((t = x >> 4) != 0) { x = t; r += 4; }
    if ((t = x >> 2) != 0) { x = t; r += 2; }
    if ((t = x >> 1) != 0) { x = t; r += 1; }
    return r;
}

std::vector<unsigned int> Digest::digestDataWords;
int Digest::digestDataSigBytes = 0;

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

    dataWords.erase(dataWords.begin(), dataWords.begin() + nWordsReady);
    digestDataWords.resize(dataWords.size());

    for (int i = 0; i < dataWords.size(); i++) digestDataWords[i] = dataWords[i];

    dataSigBytes -= nBytesReady;
    digestDataSigBytes = dataSigBytes;
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
    dataWords.resize(digestDataWords.size());
    for (int i = 0; i < digestDataWords.size(); i++) dataWords[i] = digestDataWords[i];

    dataSigBytes = digestDataSigBytes;

    size_t nBitsTotal = nDataBytes * 8;
    size_t nBitsLeft = dataSigBytes * 8;

    // Add padding
    std::vector<unsigned int> dW2(dataWords.size() + (((nBitsLeft + 64) >> 9) << 4 | 15) + 1, 0);
    for (int j = 0; j < dataWords.size(); j++) dW2[j] = dataWords[j];

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


BigInteger* m;
int mp;
int mpl;
int mph;
int um;
int mt2;

Montgomery::Montgomery(BigInteger* m) {
    this->m = m;
    this->mp = m->invDigit();
    this->mpl = this->mp & 0x7fff;
    this->mph = this->mp >> 15;
    this->um = (1 << (m->DB - 15)) - 1;
    this->mt2 = 2 * m->t;
}

Montgomery::~Montgomery() {}

// xR mod m
BigInteger* Montgomery::convert(BigInteger& x) {
    BigInteger* r = BigInteger::nbi();
    x.dlShiftTo(this->m->t, *r);
    r->divRemTo(*this->m, *r);

    BigInteger* zero = BigInteger::nbv(0);
    if (x.s < 0 && r->compareTo(*zero) > 0) this->m->subTo(*r, *r);
    delete(zero);

    return r;
}

// x/R mod m
BigInteger* Montgomery::revert(BigInteger& x) {
    BigInteger* r = BigInteger::nbi();
    x.copyTo(*r);
    this->reduce(*r);
    return r;
}

// x = x/R mod m (HAC 14.32)
void Montgomery::reduce(BigInteger& x) {
    while (x.t <= this->mt2) {	// pad x so am has enough room later
        x.data.push_back(0);
        x.t++;
    }

    for (int i = 0; i < this->m->t; ++i) {
        // faster way of calculating u0 = x[i]*mp mod DV
        int j = x.data[i] & 0x7fff;
        long long u0 = (j * this->mpl + (((j * this->mph + (x.data[i] >> 15) * this->mpl) & this->um) << 15)) & x.DM;
        // use am to combine the multiply-shift-add into one call
        j = i + this->m->t;
        x.data[j] += this->m->am(0, u0, x, i, 0, this->m->t);
        // propagate carry
        while (x.data[j] >= x.DV) { x.data[j] -= x.DV; x.data[++j]++; }
    }
    x.clamp();
    x.drShiftTo(this->m->t, x);
    if (x.compareTo(*this->m) >= 0) x.subTo(*this->m, x);
}

// r = "x^2/R mod m"; x != r
void Montgomery::sqrTo(BigInteger& x, BigInteger& r) { x.squareTo(r); this->reduce(r); }

// r = "xy/R mod m"; x,y != r
void Montgomery::mulTo(BigInteger& x, BigInteger& y, BigInteger& r) { x.multiplyTo(y, r); this->reduce(r); }


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

    std::string cleanS = this->_getCleanB64(s);
    
    std::string hex = this->_b64tohex(cleanS);

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
    }
    else if (nthList.size() > 0) {
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

std::string RSAKey::_getCleanB64(std::string str) {
    std::string ret = "";
    std::string begin = "-----BEGIN PRIVATE KEY-----";
    std::string end = "-----END PRIVATE KEY-----";

    for (int i = 0; i < str.length(); i++) {
        if (str.substr(i, begin.length()).compare(begin) == 0) {
            i += begin.length() - 1;
        }
        else if (str.substr(i, end.length()).compare(end) == 0) {
            i += end.length() - 1;
        }
        else if (str[i] != '\n' && str[i] != '\r' && str[i] != '\t' && str[i] != ' ') {
            ret += str[i];
        }
    }

    return ret;
}