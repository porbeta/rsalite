#include "pch.h"
#include "CppUnitTest.h"
#include "../Digest.h"
#include <string>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace DigestTest
{
	TEST_CLASS(DigestTest)
	{
	public:

		TEST_METHOD(urlsafeB64Encode)
		{
			std::string header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

			std::string payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}";

			std::string encodedHeader = Digest::urlsafeB64Encode(header);
			std::string encodedPayload = Digest::urlsafeB64Encode(payload);

			Assert::AreEqual("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", encodedHeader.c_str());
			Assert::AreEqual("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0", encodedPayload.c_str());
		}

		TEST_METHOD(digestStringWithSHA256)
		{
			std::string in = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
			std::string act = Digest::digestStringWithSHA256(in);

			Assert::AreEqual("8041fb8cba9e4f8cc1483790b05262841f27fdcb211bc039ddf8864374db5f53", act.c_str());
		}

		TEST_METHOD(getPaddedDigestInfoHex)
		{
			std::string act = Digest::getPaddedDigestInfoHex("8041fb8cba9e4f8cc1483790b05262841f27fdcb211bc039ddf8864374db5f53", 2048);
			Assert::AreEqual("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d0609608648016503040201050004208041fb8cba9e4f8cc1483790b05262841f27fdcb211bc039ddf8864374db5f53", act.c_str());
		}
	};
}
