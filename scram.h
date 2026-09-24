#ifdef HAVE_SSL
#ifndef GAY_PSOTNIC_SRC_SCRAM_H
#define GAY_PSOTNIC_SRC_SCRAM_H

#include <vector>
#include <sstream>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define NONCE_LENGTH 18
#define CLIENT_KEY "Client Key"
#define SERVER_KEY "Server Key"

// EVP_MD_CTX_create() and EVP_MD_CTX_destroy() were renamed in OpenSSL 1.1.0
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#define EVP_MD_CTX_new(ctx) EVP_MD_CTX_create(ctx)
#define EVP_MD_CTX_free(ctx) EVP_MD_CTX_destroy(ctx)
#endif

using std::vector;
using std::getline;
using std::stringstream;

class Scram {
public:
	enum ScramStatus {
		SCRAM_ERROR = 0,
		SCRAM_IN_PROGRESS,
		SCRAM_SUCCESS
	};

	Scram(std::string mechanism);
	~Scram();
	void authenticate(std::string input);

private:
	const EVP_MD* digest;
	size_t digestSize;
	std::string clientNonceB64;
	std::string clientFirstMessageBare;
	std::string authMessage;
	unsigned char *saltedPassword;
	unsigned int step = 0;

	int createSHA(const unsigned char *input, size_t uInputLen,
				  unsigned char *output, unsigned int *outputLen);
	ScramStatus processClientFirst();
	ScramStatus processServerFirst(std::string& input);
	ScramStatus processServerFinal(std::string& input);
};


#endif //GAY_PSOTNIC_SRC_SCRAM_H
#endif // HAVE_SSL