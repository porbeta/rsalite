#include "BigInteger.h"
#include "Montgomery.h"
#include "Digest.h"
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <random>

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
        } else if (sh + k > this->DB) {
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
    while (t > 0 && this->data[t-1] == c) --t;
}

void BigInteger::fromInt(int x) {
    this->t = 1;
    this->s = 0;

    data.resize(this->t);

    if (x > 0) this->data[0] = x;
    else if(x < -1) this->data[0] = x + this->DV;
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
        double qd = std::floor((double) r.data[i] * d1 + ((double) r.data[i - 1] + e) * d2);
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

    if (r.t > 0) r.data[r.t - 1] += this->am(i, (long long) this->data[i], r, 2 * i, 0, 1);
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
    BigInteger* r2 = nbi(), *t;
    
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
            } else { 
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

    if(lastIndex > 0) {
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

int BigInteger::_intAt(const std::string &s, int i) {
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

