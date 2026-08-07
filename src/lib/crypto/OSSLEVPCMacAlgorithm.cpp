/*
 * Copyright (c) 2017 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// TODO: Store context in securely allocated memory

/*****************************************************************************
 OSSLEVPCMacAlgorithm.cpp

 OpenSSL CMAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLEVPCMacAlgorithm.h"
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

namespace {

// Create and initialise a CMAC context for the given cipher and key
EVP_MAC_CTX* newCMACCTX(const EVP_CIPHER* cipher, const SymmetricKey* key)
{
	EVP_MAC* mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
	if (mac == NULL)
	{
		ERROR_MSG("Failed to fetch CMAC implementation");

		return NULL;
	}

	EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_MAC_CTX");

		return NULL;
	}

	// EVP_MAC_init only reads the cipher name, so casting away const is safe
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, const_cast<char*>(EVP_CIPHER_get0_name(cipher)), 0),
		OSSL_PARAM_construct_end()
	};

	if (!EVP_MAC_init(ctx, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), params))
	{
		ERROR_MSG("EVP_MAC_init failed: %s", ERR_error_string(ERR_get_error(), NULL));

		EVP_MAC_CTX_free(ctx);

		return NULL;
	}

	return ctx;
}

}

// Destructor
OSSLEVPCMacAlgorithm::~OSSLEVPCMacAlgorithm()
{
	EVP_MAC_CTX_free(curCTX);
}

// Signing functions
bool OSSLEVPCMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Determine the cipher class
	const EVP_CIPHER* cipher = getEVPCipher();
	if (cipher == NULL)
	{
		ERROR_MSG("Invalid sign mac algorithm");

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	// Initialize the context
	curCTX = newCMACCTX(cipher, key);
	if (curCTX == NULL)
	{
		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPCMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (dataToSign.size() == 0) return true;

	if (!EVP_MAC_update(curCTX, dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("EVP_MAC_update failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPCMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	size_t outLen = getMacSize();
	signature.resize(outLen);

	if (!EVP_MAC_final(curCTX, &signature[0], &outLen, signature.size()))
	{
		ERROR_MSG("EVP_MAC_final failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	signature.resize(outLen);

	EVP_MAC_CTX_free(curCTX);
	curCTX = NULL;

	return true;
}

// Verification functions
bool OSSLEVPCMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Determine the cipher class
	const EVP_CIPHER* cipher = getEVPCipher();
	if (cipher == NULL)
	{
		ERROR_MSG("Invalid verify mac algorithm");

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	// Initialize the context
	curCTX = newCMACCTX(cipher, key);
	if (curCTX == NULL)
	{
		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPCMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (originalData.size() == 0) return true;

	if (!EVP_MAC_update(curCTX, originalData.const_byte_str(), originalData.size()))
	{
		ERROR_MSG("EVP_MAC_update failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPCMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString macResult;
	size_t outLen = getMacSize();
	macResult.resize(outLen);

	if (!EVP_MAC_final(curCTX, &macResult[0], &outLen, macResult.size()))
	{
		ERROR_MSG("EVP_MAC_final failed");

		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;

		return false;
	}

	macResult.resize(outLen);

	EVP_MAC_CTX_free(curCTX);
	curCTX = NULL;

	return macResult == signature;
}
