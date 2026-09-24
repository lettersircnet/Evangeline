/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2024 evangeline development team                           *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#ifdef HAVE_SSL
#include "prots.h"
#include "global-var.h"
#include "scram.h"

static void base64Encode(std::string &str);
static int base64Decode(std::string &str);

Scram::Scram(std::string mechanism)
{
	std::string digestName;
	this->saltedPassword = nullptr;

	if (mechanism == "SCRAM-SHA-1")
	{
		digestName = "SHA1";
	}
	else if (mechanism == "SCRAM-SHA-256")
	{
		digestName = "SHA256";
	}
	else if (mechanism == "SCRAM-SHA-512")
	{
		digestName = "SHA512";
	}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	OpenSSL_add_all_algorithms();
#endif
	this->digest = EVP_get_digestbyname(digestName.c_str());

	if (this->digest == nullptr)
	{
		std::string errorMessage = "Unknown message digest: " + digestName;
		net.send(HAS_N, errorMessage.c_str(), NULL);
		throw std::invalid_argument(errorMessage);
	}

	this->digestSize = EVP_MD_size(this->digest);
}

Scram::~Scram()
{
	if (this->saltedPassword != nullptr)
	{
		free(this->saltedPassword);
	}
}

int Scram::createSHA(const unsigned char *input, size_t inputLen,
					 unsigned char *output, unsigned int *outputLen)
{
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();

	if (!EVP_DigestInit_ex(mdCtx, this->digest, NULL))
	{
		net.send(HAS_N, "Message digest initialization failed", NULL);
		EVP_MD_CTX_free(mdCtx);
		return SCRAM_ERROR;
	}

	if (!EVP_DigestUpdate(mdCtx, input, inputLen))
	{
		net.send(HAS_N, "Message digest update failed", NULL);
		EVP_MD_CTX_free(mdCtx);
		return SCRAM_ERROR;
	}

	if (!EVP_DigestFinal_ex(mdCtx, output, outputLen))
	{
		net.send(HAS_N, "Message digest finalization failed", NULL);
		EVP_MD_CTX_free(mdCtx);
		return SCRAM_ERROR;
	}

	EVP_MD_CTX_free(mdCtx);
	return SCRAM_IN_PROGRESS;
}

Scram::ScramStatus Scram::processClientFirst()
{
	char nonce[NONCE_LENGTH];
	std::string output;

	RAND_bytes((unsigned char *) nonce, NONCE_LENGTH);
	this->clientNonceB64 = std::string(nonce);
	base64Encode(this->clientNonceB64);
	output = "n,,n=" + std::string(config.sasl_username) + ",r=" + this->clientNonceB64;
	this->clientFirstMessageBare = output.substr(3);
	base64Encode(output);
	ME.sendAuthentication(output.c_str());

	this->step++;
	return SCRAM_IN_PROGRESS;
}

Scram::ScramStatus Scram::processServerFirst(std::string &input)
{
	std::string clientFinalMessageWithoutProof, serverNonceB64, salt, clientProofB64;
	std::vector<std::string> vsParams;
	std::string segment;
	unsigned char *clientKey, storedKey[EVP_MAX_MD_SIZE];
	unsigned char *clientSignature, *clientProof;
	unsigned int index, iterCount = 0, clientKeyLen, storedKeyLen;
	unsigned long saltLen;
	size_t clientNonceLen;
	std::string password = std::string(config.sasl_password);
	std::string output;
	std::stringstream inputStream(input);

	while (std::getline(inputStream, segment, ','))
	{
		vsParams.push_back(segment);
	}

	if (vsParams.size() < 3)
	{
		net.send(HAS_N, "Invalid server-first-message: ", input.c_str(), NULL);
		return SCRAM_ERROR;
	}

	for (const std::string &param: vsParams)
	{
		if (!strncmp(param.c_str(), "r=", 2))
		{
			serverNonceB64 = param.substr(2);
		}
		else if (!strncmp(param.c_str(), "s=", 2))
		{
			salt = param.substr(2);
		}
		else if (!strncmp(param.c_str(), "i=", 2))
		{
			iterCount = strtoul(param.substr(2).c_str(), NULL, 10);
		}
	}

	if (serverNonceB64.empty() || salt.empty() || iterCount == 0)
	{
		net.send(HAS_N, "Invalid server-first-message: ", input.c_str(), NULL);
		return SCRAM_ERROR;
	}
	clientNonceLen = this->clientNonceB64.length();

	// The server can append his nonce to the client's nonce
	if (serverNonceB64.length() < clientNonceLen ||
		strncmp(serverNonceB64.c_str(), this->clientNonceB64.c_str(), clientNonceLen))
	{
		net.send(HAS_N, "Invalid server nonce: ", serverNonceB64.c_str(), NULL);
		return SCRAM_ERROR;
	}
	saltLen = base64Decode(salt);

	// SaltedPassword := Hi(Normalize(password), salt, i)
	this->saltedPassword = static_cast<unsigned char *>(malloc(this->digestSize));
	PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
					  (unsigned char *) salt.c_str(), saltLen, iterCount,
					  this->digest, this->digestSize, this->saltedPassword);

	// AuthMessage := client-first-message-bare + "," +
	//                server-first-message + "," +
	//                client-final-message-without-proof
	clientFinalMessageWithoutProof = "c=biws,r=" + serverNonceB64;
	this->authMessage = this->clientFirstMessageBare + "," + input + "," + clientFinalMessageWithoutProof;

	// ClientKey := HMAC(SaltedPassword, "Client Key")
	clientKey = static_cast<unsigned char *>(malloc(this->digestSize));
	HMAC(this->digest, this->saltedPassword, this->digestSize,
		 (unsigned char *) CLIENT_KEY, strlen(CLIENT_KEY), clientKey, &clientKeyLen);

	// StoredKey := H(ClientKey)
	if (!createSHA(clientKey, this->digestSize, storedKey, &storedKeyLen))
	{
		free(clientKey);
		return SCRAM_ERROR;
	}

	// ClientSignature := HMAC(StoredKey, AuthMessage)
	clientSignature = static_cast<unsigned char *>(malloc(this->digestSize));
	memset(clientSignature, 0, this->digestSize);
	HMAC(this->digest, storedKey, storedKeyLen,
		 (unsigned char *) this->authMessage.c_str(), this->authMessage.length(),
		 clientSignature, NULL);

	// ClientProof := ClientKey XOR ClientSignature
	clientProof = static_cast<unsigned char *>(malloc(clientKeyLen));
	memset(clientProof, 0, clientKeyLen);
	for (index = 0; index < clientKeyLen; index++)
	{
		clientProof[index] = clientKey[index] ^ clientSignature[index];
	}

	clientProofB64 = std::string((const char *) clientProof, clientKeyLen);
	base64Encode(clientProofB64);
	output = clientFinalMessageWithoutProof + ",p=" + clientProofB64;
	base64Encode(output);
	ME.sendAuthentication(output.c_str());
	free(clientKey);
	free(clientSignature);
	free(clientProof);
	this->step++;
	return SCRAM_IN_PROGRESS;
}

Scram::ScramStatus Scram::processServerFinal(std::string &input)
{
	std::string verifier;
	unsigned char *serverKey, *serverSignature;
	unsigned int serverKeyLen = 0, serverSignatureLen = 0;
	unsigned long verifierLen;

	if (input.length() < 3 || (input[0] != 'v' && input[1] != '='))
	{
		net.send(HAS_N, "SCRAM: invalid server-final-message", NULL);
		return SCRAM_ERROR;
	}

	verifier = input.substr(2);
	verifierLen = base64Decode(verifier);

	// ServerKey := HMAC(SaltedPassword, "Server Key")
	serverKey = static_cast<unsigned char *>(malloc(this->digestSize));
	HMAC(this->digest, this->saltedPassword, this->digestSize,
		 (unsigned char *) SERVER_KEY, strlen(SERVER_KEY), serverKey,
		 &serverKeyLen);

	// ServerSignature := HMAC(ServerKey, AuthMessage)
	serverSignature = static_cast<unsigned char *>(malloc(this->digestSize));
	HMAC(this->digest, serverKey, this->digestSize,
		 (unsigned char *) this->authMessage.c_str(), this->authMessage.length(),
		 serverSignature, &serverSignatureLen);

	if (verifierLen == serverSignatureLen &&
		memcmp(verifier.c_str(), serverSignature, verifierLen) == 0)
	{
		free(serverKey);
		free(serverSignature);
		return SCRAM_SUCCESS;
	}
	else
	{
		net.send(HAS_N, "SCRAM: Failed to verify server signature", NULL);
		free(serverKey);
		free(serverSignature);
		return SCRAM_ERROR;
	}
}

void Scram::authenticate(std::string input)
{
	ScramStatus status;

	if (input != "+")
	{
		base64Decode(input);
	}

	switch (this->step)
	{
		case 0:
			status = processClientFirst();
			break;
		case 1:
			status = processServerFirst(input);
			break;
		case 2:
			status = processServerFinal(input);
			break;
		default:
			status = SCRAM_ERROR;
			break;
	}

	if (status == Scram::SCRAM_SUCCESS)
	{
		DEBUG(printf("SCRAM authentication succeeded\n"));
		net.irc.send("AUTHENTICATE +", NULL);
	}
	else if (status == Scram::SCRAM_ERROR)
	{
		DEBUG(printf("SCRAM authentication failed\n"));
		net.irc.send("QUIT :changing servers", NULL);
	}
}

static void base64Encode(std::string &str)
{
	char *p = encode_base64(str.size(), (unsigned char *) str.c_str());
	str.clear();
	str.append(p);
	free(p);
}

static int base64Decode(std::string &str)
{
	char dest[MAX_LEN];
	int len = decode_base64((unsigned char *) dest, str.c_str());
	dest[len] = '\0';
	str.clear();
	str.append(dest, len);
	return len;
}
#endif