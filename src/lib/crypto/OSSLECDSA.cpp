/*
 * Copyright (c) 2010 SURFnet bv
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

/*****************************************************************************
 OSSLECDSA.cpp

 OpenSSL ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECDSA.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "OSSLECKeyPair.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>

namespace {

// Sign a digest, returning the r,s pair as a zero-padded fixed-width big-endian pair
bool ecdsaSignRaw(EVP_PKEY* pkey, const ByteString& data, ByteString& signature, size_t len)
{
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	size_t derLen = 0;
	ByteString der;

	if (ctx == NULL ||
	    EVP_PKEY_sign_init(ctx) <= 0 ||
	    EVP_PKEY_sign(ctx, NULL, &derLen, data.const_byte_str(), data.size()) <= 0)
	{
		ERROR_MSG("ECDSA sign failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	der.resize(derLen);
	if (EVP_PKEY_sign(ctx, &der[0], &derLen, data.const_byte_str(), data.size()) <= 0)
	{
		ERROR_MSG("ECDSA sign failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// EVP_PKEY_sign emits a DER ECDSA-Sig-Value, but PKCS#11 wants raw r||s
	const unsigned char* derPtr = der.const_byte_str();
	ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &derPtr, derLen);
	if (sig == NULL) return false;

	const BIGNUM* bn_r = NULL;
	const BIGNUM* bn_s = NULL;
	ECDSA_SIG_get0(sig, &bn_r, &bn_s);

	signature.resize(2 * len);
	memset(&signature[0], 0, 2 * len);
	BN_bn2bin(bn_r, &signature[len - BN_num_bytes(bn_r)]);
	BN_bn2bin(bn_s, &signature[2 * len - BN_num_bytes(bn_s)]);
	ECDSA_SIG_free(sig);

	return true;
}

// Verify a raw r,s pair against a digest
bool ecdsaVerifyRaw(EVP_PKEY* pkey, const ByteString& data, const ByteString& signature, size_t len)
{
	ECDSA_SIG* sig = ECDSA_SIG_new();
	if (sig == NULL)
	{
		ERROR_MSG("Could not create an ECDSA_SIG object");
		return false;
	}

	const unsigned char* s = signature.const_byte_str();
	BIGNUM* bn_r = BN_bin2bn(s, len, NULL);
	BIGNUM* bn_s = BN_bin2bn(s + len, len, NULL);
	if (bn_r == NULL || bn_s == NULL || !ECDSA_SIG_set0(sig, bn_r, bn_s))
	{
		ERROR_MSG("Could not add data to the ECDSA_SIG object");
		BN_free(bn_r);
		BN_free(bn_s);
		ECDSA_SIG_free(sig);
		return false;
	}

	unsigned char* der = NULL;
	int derLen = i2d_ECDSA_SIG(sig, &der);
	ECDSA_SIG_free(sig);
	if (derLen <= 0) return false;

	int ret = -1;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (ctx != NULL && EVP_PKEY_verify_init(ctx) > 0)
	{
		ret = EVP_PKEY_verify(ctx, der, derLen, data.const_byte_str(), data.size());
	}

	if (ret < 0)
		ERROR_MSG("ECDSA verify failed (0x%08X)", ERR_get_error());

	EVP_PKEY_CTX_free(ctx);
	OPENSSL_free(der);

	return ret == 1;
}

}

// Constructor
OSSLECDSA::OSSLECDSA()
{
	pCurrentHash = NULL;
}

// Destructor
OSSLECDSA::~OSSLECDSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}
}

// Signing functions
bool OSSLECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const MechanismParam* /* mechanismParam */)
{

	HashAlgo::Type hash = HashAlgo::Unknown;

	if (mechanism != AsymMech::ECDSA)
	{
		switch (mechanism)
		{
			case AsymMech::ECDSA_SHA1:
				hash = HashAlgo::SHA1;
				break;
			case AsymMech::ECDSA_SHA224:
				hash = HashAlgo::SHA224;
				break;
			case AsymMech::ECDSA_SHA256:
				hash = HashAlgo::SHA256;
				break;
			case AsymMech::ECDSA_SHA384:
				hash = HashAlgo::SHA384;
				break;
			case AsymMech::ECDSA_SHA512:
				hash = HashAlgo::SHA512;
				break;
			case AsymMech::ECDSA_SHA3_224:
				hash = HashAlgo::SHA3_224;
				break;
			case AsymMech::ECDSA_SHA3_256:
				hash = HashAlgo::SHA3_256;
				break;
			case AsymMech::ECDSA_SHA3_384:
				hash = HashAlgo::SHA3_384;
				break;
			case AsymMech::ECDSA_SHA3_512:
				hash = HashAlgo::SHA3_512;
				break;
			default:
				ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
				return false;
		}
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLECPrivateKey* pk = (OSSLECPrivateKey*) privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}

	// Pre-hash the data if necessary
	ByteString prepDataToSign;
	if (hash == HashAlgo::Unknown) {
		prepDataToSign = dataToSign;
	} else {
		HashAlgorithm* digest = CryptoFactory::i()->getHashAlgorithm(hash);

		if (!digest->hashInit()
				|| !digest->hashUpdate(dataToSign)
				|| !digest->hashFinal(prepDataToSign))
		{
			delete digest;
			return false;
		}
		delete digest;
	}


	// Perform the signature operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}

	return ecdsaSignRaw(pkey, prepDataToSign, signature, len);
}

bool OSSLECDSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			 const MechanismParam* mechanismParam /* = NULL */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, mechanismParam))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	HashAlgo::Type hash = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::ECDSA_SHA1:
			hash = HashAlgo::SHA1;
			break;
		case AsymMech::ECDSA_SHA224:
			hash = HashAlgo::SHA224;
			break;
		case AsymMech::ECDSA_SHA256:
			hash = HashAlgo::SHA256;
			break;
		case AsymMech::ECDSA_SHA384:
			hash = HashAlgo::SHA384;
			break;
		case AsymMech::ECDSA_SHA512:
			hash = HashAlgo::SHA512;
			break;
		case AsymMech::ECDSA_SHA3_224:
			hash = HashAlgo::SHA3_224;
			break;
		case AsymMech::ECDSA_SHA3_256:
			hash = HashAlgo::SHA3_256;
			break;
		case AsymMech::ECDSA_SHA3_384:
			hash = HashAlgo::SHA3_384;
			break;
		case AsymMech::ECDSA_SHA3_512:
			hash = HashAlgo::SHA3_512;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLECDSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLECDSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	OSSLECPrivateKey* pk = (OSSLECPrivateKey*) currentPrivateKey;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bResult)
	{
		return false;
	}

	// Get the OpenSSL key
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}

	// Perform the signature operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}

	return ecdsaSignRaw(pkey, hash, signature, len);
}

// Verification functions
bool OSSLECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const MechanismParam* /* mechanismParam */)
{

	HashAlgo::Type hash = HashAlgo::Unknown;

	if (mechanism != AsymMech::ECDSA)
    {
        switch (mechanism)
        {
            case AsymMech::ECDSA_SHA1:
                hash = HashAlgo::SHA1;
                break;
            case AsymMech::ECDSA_SHA224:
                hash = HashAlgo::SHA224;
                break;
            case AsymMech::ECDSA_SHA256:
                hash = HashAlgo::SHA256;
                break;
            case AsymMech::ECDSA_SHA384:
                hash = HashAlgo::SHA384;
                break;
            case AsymMech::ECDSA_SHA512:
                hash = HashAlgo::SHA512;
                break;
            case AsymMech::ECDSA_SHA3_224:
                hash = HashAlgo::SHA3_224;
                break;
            case AsymMech::ECDSA_SHA3_256:
                hash = HashAlgo::SHA3_256;
                break;
            case AsymMech::ECDSA_SHA3_384:
                hash = HashAlgo::SHA3_384;
                break;
            case AsymMech::ECDSA_SHA3_512:
                hash = HashAlgo::SHA3_512;
                break;
            default:
                ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
                return false;
        }
    }

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLECPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLECPublicKey* pk = (OSSLECPublicKey*) publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}

	// Perform the verify operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	if (signature.size() != 2 * len)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}

	// Pre-hash the data if necessary
	ByteString prepDataToSign;
	if (hash == HashAlgo::Unknown) {
		prepDataToSign = originalData;
	} else {
		HashAlgorithm* digest = CryptoFactory::i()->getHashAlgorithm(hash);

		if (!digest->hashInit()
				|| !digest->hashUpdate(originalData)
				|| !digest->hashFinal(prepDataToSign))
		{
			delete digest;
			return false;
		}
		delete digest;
	}

	return ecdsaVerifyRaw(pkey, prepDataToSign, signature, len);
}

bool OSSLECDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			   const MechanismParam* mechanismParam /* = NULL */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, mechanismParam))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLECPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	HashAlgo::Type hash = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::ECDSA_SHA1:
			hash = HashAlgo::SHA1;
			break;
		case AsymMech::ECDSA_SHA224:
			hash = HashAlgo::SHA224;
			break;
		case AsymMech::ECDSA_SHA256:
			hash = HashAlgo::SHA256;
			break;
		case AsymMech::ECDSA_SHA384:
			hash = HashAlgo::SHA384;
			break;
		case AsymMech::ECDSA_SHA512:
			hash = HashAlgo::SHA512;
			break;
		case AsymMech::ECDSA_SHA3_224:
			hash = HashAlgo::SHA3_224;
			break;
		case AsymMech::ECDSA_SHA3_256:
			hash = HashAlgo::SHA3_256;
			break;
		case AsymMech::ECDSA_SHA3_384:
			hash = HashAlgo::SHA3_384;
			break;
		case AsymMech::ECDSA_SHA3_512:
			hash = HashAlgo::SHA3_512;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLECDSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLECDSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	OSSLECPublicKey* pk = (OSSLECPublicKey*) currentPublicKey;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bResult)
	{
		return false;
	}

	// Get the OpenSSL key
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}

	// Perform the verify operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	if (signature.size() != 2 * len)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}

	return ecdsaVerifyRaw(pkey, hash, signature, len);
}

// Encryption functions
bool OSSLECDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/, const MechanismParam* /*mechanismParam*/ )
{
	ERROR_MSG("ECDSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLECDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/, const MechanismParam* /*mechanismParam*/)  
{
	ERROR_MSG("ECDSA does not support decryption");

	return false;
}

// Key factory
bool OSSLECDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDSA key generation");

		return false;
	}

	ECParameters* params = (ECParameters*) parameters;

	// Generate the key-pair from the supplied domain parameters
	EVP_PKEY* domain = OSSL::ec2PKey(params->getEC(), NULL, NULL);
	if (domain == NULL)
	{
		ERROR_MSG("Failed to instantiate the EC domain parameters");

		return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, domain, NULL);
	EVP_PKEY* pkey = NULL;

	if (ctx == NULL ||
	    EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		ERROR_MSG("ECDSA key generation failed (0x%08X)", ERR_get_error());

		EVP_PKEY_free(pkey);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(domain);

		return false;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(domain);

	// Create an asymmetric key-pair object to return
	OSSLECKeyPair* kp = new OSSLECKeyPair();

	((OSSLECPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLECPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

unsigned long OSSLECDSA::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long OSSLECDSA::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool OSSLECDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLECKeyPair* kp = new OSSLECKeyPair();

	bool rv = true;

	if (!((ECPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((ECPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
	{
		rv = false;
	}

	if (!rv)
	{
		delete kp;

		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool OSSLECDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLECPublicKey* pub = new OSSLECPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLECDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLECPrivateKey* priv = new OSSLECPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLECDSA::newPublicKey()
{
	return (PublicKey*) new OSSLECPublicKey();
}

PrivateKey* OSSLECDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLECPrivateKey();
}

AsymmetricParameters* OSSLECDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLECDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ECParameters* params = new ECParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
