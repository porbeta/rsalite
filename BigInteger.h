#pragma once
#include <string>
#include <vector>
#include <map>

#ifndef BIGINTEGER_H
#define BIGINTEGER_H

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

    std::vector<uint32_t> data;
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
    uint32_t am(int i, double x, BigInteger& w, int j, double c, int n);
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
    uint32_t intValue();

private:
    std::map<int, int> BI_RC;
    const std::string BI_RM;

    void _init();
    int _intAt(const std::string& s, int i);
    int _nbits(uint32_t x);
};

#endif