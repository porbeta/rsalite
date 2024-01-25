#include "Montgomery.h"


BigInteger *m;
int mp;
int mpl;
int mph;
int um;
int mt2;

Montgomery::Montgomery(BigInteger *m) {
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