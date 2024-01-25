#pragma once
#include "BigInteger.h"

#ifndef MONTGOMERY_H
#define MONTGOMERY_H

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

#endif