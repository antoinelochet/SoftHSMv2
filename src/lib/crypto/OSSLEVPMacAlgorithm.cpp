/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 OSSLEVPMacAlgorithm.cpp

 OpenSSL MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLEVPMacAlgorithm.h"
#include <openssl/core_names.h>
#include <openssl/params.h>

namespace {

// Create and initialise an HMAC context for the given digest and key
EVP_MAC_CTX* newHMACCTX(const EVP_MD* md, const SymmetricKey* key)
{
	EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (mac == NULL)
	{
		ERROR_MSG("Failed to fetch HMAC implementation");

		return NULL;
	}

	EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_MAC_CTX");

		return NULL;
	}

	// EVP_MAC_init only reads the digest name, so casting away const is safe
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>(EVP_MD_get0_name(md)), 0),
		OSSL_PARAM_construct_end()
	};

	if (!EVP_MAC_init(ctx, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), params))
	{
		ERROR_MSG("EVP_MAC_init failed");

		EVP_MAC_CTX_free(ctx);

		return NULL;
	}

	return ctx;
}

}

// Destructor
OSSLEVPMacAlgorithm::~OSSLEVPMacAlgorithm()
{
	EVP_MAC_CTX_free(curCTX);
}

// Signing functions
bool OSSLEVPMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Initialize the context
	curCTX = newHMACCTX(getEVPHash(), key);
	if (curCTX == NULL)
	{
		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	// The GOST implementation in OpenSSL will segfault if we update with zero length.
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

bool OSSLEVPMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	signature.resize(EVP_MD_get_size(getEVPHash()));
	size_t outLen = signature.size();

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
bool OSSLEVPMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Initialize the context
	curCTX = newHMACCTX(getEVPHash(), key);
	if (curCTX == NULL)
	{
		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLEVPMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	// The GOST implementation in OpenSSL will segfault if we update with zero length.
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

bool OSSLEVPMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString macResult;
	size_t outLen = EVP_MD_get_size(getEVPHash());
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
