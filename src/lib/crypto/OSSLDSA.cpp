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
 OSSLDSA.cpp

 OpenSSL DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDSA.h"
#include "CryptoFactory.h"
#include "DSAParameters.h"
#include "OSSLDSAKeyPair.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

namespace {

// Sign a digest, returning the r,s pair as a zero-padded fixed-width big-endian pair
bool dsaSignRaw(EVP_PKEY* pkey, const unsigned char* data, size_t dataLen,
		ByteString& signature, unsigned int sigLen)
{
	if (pkey == NULL) return false;

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	size_t derLen = 0;
	ByteString der;

	if (ctx == NULL ||
	    EVP_PKEY_sign_init(ctx) <= 0 ||
	    EVP_PKEY_sign(ctx, NULL, &derLen, data, dataLen) <= 0)
	{
		ERROR_MSG("DSA sign failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	der.resize(derLen);
	if (EVP_PKEY_sign(ctx, &der[0], &derLen, data, dataLen) <= 0)
	{
		ERROR_MSG("DSA sign failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// EVP_PKEY_sign emits a DER DSA-Sig-Value, but PKCS#11 wants raw r||s
	const unsigned char* derPtr = der.const_byte_str();
	DSA_SIG* sig = d2i_DSA_SIG(NULL, &derPtr, derLen);
	if (sig == NULL) return false;

	const BIGNUM* bn_r = NULL;
	const BIGNUM* bn_s = NULL;
	DSA_SIG_get0(sig, &bn_r, &bn_s);

	signature.resize(sigLen);
	memset(&signature[0], 0, sigLen);
	BN_bn2bin(bn_r, &signature[sigLen / 2 - BN_num_bytes(bn_r)]);
	BN_bn2bin(bn_s, &signature[sigLen - BN_num_bytes(bn_s)]);
	DSA_SIG_free(sig);

	return true;
}

// Verify a raw r,s pair against a digest
bool dsaVerifyRaw(EVP_PKEY* pkey, const unsigned char* data, size_t dataLen,
		  const ByteString& signature, unsigned int sigLen)
{
	if (pkey == NULL) return false;

	DSA_SIG* sig = DSA_SIG_new();
	if (sig == NULL) return false;

	const unsigned char* s = signature.const_byte_str();
	BIGNUM* bn_r = BN_bin2bn(s, sigLen / 2, NULL);
	BIGNUM* bn_s = BN_bin2bn(s + sigLen / 2, sigLen / 2, NULL);
	if (bn_r == NULL || bn_s == NULL || !DSA_SIG_set0(sig, bn_r, bn_s))
	{
		BN_free(bn_r);
		BN_free(bn_s);
		DSA_SIG_free(sig);
		return false;
	}

	unsigned char* der = NULL;
	int derLen = i2d_DSA_SIG(sig, &der);
	DSA_SIG_free(sig);
	if (derLen <= 0) return false;

	int ret = -1;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (ctx != NULL && EVP_PKEY_verify_init(ctx) > 0)
	{
		ret = EVP_PKEY_verify(ctx, der, derLen, data, dataLen);
	}

	if (ret < 0)
		ERROR_MSG("DSA verify failed (0x%08X)", ERR_get_error());

	EVP_PKEY_CTX_free(ctx);
	OPENSSL_free(der);

	return ret == 1;
}

}

// Constructor
OSSLDSA::OSSLDSA()
{
	pCurrentHash = NULL;
}

// Destructor
OSSLDSA::~OSSLDSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}
}

// Signing functions
bool OSSLDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		   ByteString& signature, const AsymMech::Type mechanism,
		   const MechanismParam* mechanismParam )
{
	if (mechanism == AsymMech::DSA)
	{
		// Separate implementation for DSA signing without hash computation

		// Check if the private key is the right type
		if (!privateKey->isOfType(OSSLDSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		OSSLDSAPrivateKey* pk = (OSSLDSAPrivateKey*) privateKey;

		return dsaSignRaw(pk->getOSSLKey(), dataToSign.const_byte_str(), dataToSign.size(),
				  signature, pk->getOutputLength());
	}
	else
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, mechanismParam);
	}
}

bool OSSLDSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			   const MechanismParam* mechanismParam)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, mechanismParam))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	HashAlgo::Type hash = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::DSA_SHA1:
			hash = HashAlgo::SHA1;
			break;
		case AsymMech::DSA_SHA224:
			hash = HashAlgo::SHA224;
			break;
		case AsymMech::DSA_SHA256:
			hash = HashAlgo::SHA256;
			break;
		case AsymMech::DSA_SHA384:
			hash = HashAlgo::SHA384;
			break;
		case AsymMech::DSA_SHA512:
			hash = HashAlgo::SHA512;
			break;
		case AsymMech::DSA_SHA3_224:
			hash = HashAlgo::SHA3_224;
			break;
		case AsymMech::DSA_SHA3_256:
			hash = HashAlgo::SHA3_256;
			break;
		case AsymMech::DSA_SHA3_384:
			hash = HashAlgo::SHA3_384;
			break;
		case AsymMech::DSA_SHA3_512:
			hash = HashAlgo::SHA3_512;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash);

	if (pCurrentHash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if (!pCurrentHash->hashInit())
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLDSA::signUpdate(const ByteString& dataToSign)
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

bool OSSLDSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	OSSLDSAPrivateKey* pk = (OSSLDSAPrivateKey*) currentPrivateKey;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bFirstResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bFirstResult)
	{
		return false;
	}

	return dsaSignRaw(pk->getOSSLKey(), &hash[0], hash.size(), signature, pk->getOutputLength());
}

// Verification functions
bool OSSLDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		     const ByteString& signature, const AsymMech::Type mechanism,
		     const MechanismParam* mechanismParam)
{
	if (mechanism == AsymMech::DSA)
	{
		// Separate implementation for DSA verification without hash computation

		// Check if the private key is the right type
		if (!publicKey->isOfType(OSSLDSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the verify operation
		OSSLDSAPublicKey* pk = (OSSLDSAPublicKey*) publicKey;
		unsigned int sigLen = pk->getOutputLength();
		if (signature.size() != sigLen)
			return false;

		return dsaVerifyRaw(pk->getOSSLKey(), originalData.const_byte_str(), originalData.size(),
				    signature, sigLen);
	}
	else
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, mechanismParam);
	}
}

bool OSSLDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			 const MechanismParam* mechanismParam)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, mechanismParam))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	HashAlgo::Type hash = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::DSA_SHA1:
			hash = HashAlgo::SHA1;
			break;
		case AsymMech::DSA_SHA224:
			hash = HashAlgo::SHA224;
			break;
		case AsymMech::DSA_SHA256:
			hash = HashAlgo::SHA256;
			break;
		case AsymMech::DSA_SHA384:
			hash = HashAlgo::SHA384;
			break;
		case AsymMech::DSA_SHA512:
			hash = HashAlgo::SHA512;
			break;
		case AsymMech::DSA_SHA3_224:
			hash = HashAlgo::SHA3_224;
			break;
		case AsymMech::DSA_SHA3_256:
			hash = HashAlgo::SHA3_256;
			break;
		case AsymMech::DSA_SHA3_384:
			hash = HashAlgo::SHA3_384;
			break;
		case AsymMech::DSA_SHA3_512:
			hash = HashAlgo::SHA3_512;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash);


	if (pCurrentHash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if (!pCurrentHash->hashInit())
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLDSA::verifyUpdate(const ByteString& originalData)
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

bool OSSLDSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	OSSLDSAPublicKey* pk = (OSSLDSAPublicKey*) currentPublicKey;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bFirstResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bFirstResult)
	{
		return false;
	}

	// Perform the verify operation
	unsigned int sigLen = pk->getOutputLength();
	if (signature.size() != sigLen)
		return false;

	return dsaVerifyRaw(pk->getOSSLKey(), &hash[0], hash.size(), signature, sigLen);
}

// Encryption functions
bool OSSLDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
		      ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/,
			  const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("DSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
		      ByteString& /*data*/, const AsymMech::Type /*padding*/,
			  const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("DSA does not support decryption");

	return false;
}

// Key factory
bool OSSLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(DSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for DSA key generation");

		return false;
	}

	DSAParameters* params = (DSAParameters*) parameters;

	// Build the domain parameters, then generate a key from them
	BIGNUM* bn_p = OSSL::byteString2bn(params->getP());
	BIGNUM* bn_q = OSSL::byteString2bn(params->getQ());
	BIGNUM* bn_g = OSSL::byteString2bn(params->getG());

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM* osslParams = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	EVP_PKEY_CTX* kctx = NULL;
	EVP_PKEY* domain = NULL;
	EVP_PKEY* pkey = NULL;
	bool ok = false;

	if (bld != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p) &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, bn_q) &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g) &&
	    (osslParams = OSSL_PARAM_BLD_to_param(bld)) != NULL &&
	    (pctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL)) != NULL &&
	    EVP_PKEY_fromdata_init(pctx) > 0 &&
	    EVP_PKEY_fromdata(pctx, &domain, EVP_PKEY_KEY_PARAMETERS, osslParams) > 0 &&
	    (kctx = EVP_PKEY_CTX_new_from_pkey(NULL, domain, NULL)) != NULL &&
	    EVP_PKEY_keygen_init(kctx) > 0 &&
	    EVP_PKEY_keygen(kctx, &pkey) > 0)
	{
		ok = true;
	}
	else
	{
		ERROR_MSG("DSA key generation failed (0x%08X)", ERR_get_error());
	}

	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(domain);
	OSSL_PARAM_free(osslParams);
	OSSL_PARAM_BLD_free(bld);
	BN_free(bn_p);
	BN_free(bn_q);
	BN_free(bn_g);

	if (!ok)
	{
		EVP_PKEY_free(pkey);

		return false;
	}

	// Create an asymmetric key-pair object to return
	OSSLDSAKeyPair* kp = new OSSLDSAKeyPair();

	((OSSLDSAPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLDSAPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

unsigned long OSSLDSA::getMinKeySize()
{
#ifdef WITH_FIPS
	// OPENSSL_DSA_FIPS_MIN_MODULUS_BITS is 1024
	return 1024;
#else
	return 512;
#endif
}

unsigned long OSSLDSA::getMaxKeySize()
{
	return OPENSSL_DSA_MAX_MODULUS_BITS;
}

bool OSSLDSA::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
{
	if ((ppParams == NULL) || (parameters == NULL))
	{
		return false;
	}

	size_t bitLen = (size_t) parameters;

	if (bitLen < getMinKeySize() || bitLen > getMaxKeySize())
	{
		ERROR_MSG("This DSA key size is not supported");

		return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
	EVP_PKEY* pkey = NULL;
	unsigned int pbits = (unsigned int) bitLen;
	OSSL_PARAM osslParams[] = {
		OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_PBITS, &pbits),
		OSSL_PARAM_construct_end()
	};

	if (ctx == NULL ||
	    EVP_PKEY_paramgen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_params(ctx, osslParams) <= 0 ||
	    EVP_PKEY_paramgen(ctx, &pkey) <= 0)
	{
		ERROR_MSG("Failed to generate %d bit DSA parameters", bitLen);

		EVP_PKEY_free(pkey);
		EVP_PKEY_CTX_free(ctx);

		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	BIGNUM* bn_p = NULL;
	BIGNUM* bn_q = NULL;
	BIGNUM* bn_g = NULL;

	if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &bn_p) ||
	    !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &bn_q) ||
	    !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &bn_g))
	{
		ERROR_MSG("Failed to retrieve the generated DSA parameters");

		BN_free(bn_p);
		BN_free(bn_q);
		BN_free(bn_g);
		EVP_PKEY_free(pkey);

		return false;
	}

	// Store the DSA parameters
	DSAParameters* params = new DSAParameters();

	ByteString p = OSSL::bn2ByteString(bn_p); params->setP(p);
	ByteString q = OSSL::bn2ByteString(bn_q); params->setQ(q);
	ByteString g = OSSL::bn2ByteString(bn_g); params->setG(g);

	*ppParams = params;

	BN_free(bn_p);
	BN_free(bn_q);
	BN_free(bn_g);
	EVP_PKEY_free(pkey);

	return true;
}

bool OSSLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLDSAKeyPair* kp = new OSSLDSAKeyPair();

	bool rv = true;

	if (!((DSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((DSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool OSSLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDSAPublicKey* pub = new OSSLDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDSAPrivateKey* priv = new OSSLDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLDSA::newPublicKey()
{
	return (PublicKey*) new OSSLDSAPublicKey();
}

PrivateKey* OSSLDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLDSAPrivateKey();
}

AsymmetricParameters* OSSLDSA::newParameters()
{
	return (AsymmetricParameters*) new DSAParameters();
}

bool OSSLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	DSAParameters* params = new DSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}

