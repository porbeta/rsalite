#pragma once

#ifndef RSALITE_H
#define RSALITE_H

class RSALite
{
public:
	static char* createJWT(char* h, int hLen, char* pl, int plLen, char* pKey, char pKeyLen);
};

#endif