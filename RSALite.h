#pragma once
#include <string>

#ifndef RSALITE_H
#define RSALITE_H

class RSALite
{
public:
	static std::string createJWT(std::string header, std::string payload, std::string privateKey);
};

#endif