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
 OSSLDSAPublicKey.cpp

 OpenSSL DSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDSAPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <string.h>

// Constructors
OSSLDSAPublicKey::OSSLDSAPublicKey()
{
	pkey = NULL;
}

OSSLDSAPublicKey::OSSLDSAPublicKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLDSAPublicKey::~OSSLDSAPublicKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLDSAPublicKey::type = "OpenSSL DSA Public Key";

// Set from OpenSSL representation
void OSSLDSAPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	BIGNUM* bn_p = NULL;
	BIGNUM* bn_q = NULL;
	BIGNUM* bn_g = NULL;
	BIGNUM* bn_pub_key = NULL;

	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_FFC_P, &bn_p))
	{
		ByteString inP = OSSL::bn2ByteString(bn_p);
		setP(inP);
		BN_free(bn_p);
	}
	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_FFC_Q, &bn_q))
	{
		ByteString inQ = OSSL::bn2ByteString(bn_q);
		setQ(inQ);
		BN_free(bn_q);
	}
	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_FFC_G, &bn_g))
	{
		ByteString inG = OSSL::bn2ByteString(bn_g);
		setG(inG);
		BN_free(bn_g);
	}
	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_PUB_KEY, &bn_pub_key))
	{
		ByteString inY = OSSL::bn2ByteString(bn_pub_key);
		setY(inY);
		BN_free(bn_pub_key);
	}
}

// Check if the key is of the given type
bool OSSLDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DSA public key components
void OSSLDSAPublicKey::setP(const ByteString& inP)
{
	DSAPublicKey::setP(inP);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

void OSSLDSAPublicKey::setQ(const ByteString& inQ)
{
	DSAPublicKey::setQ(inQ);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

void OSSLDSAPublicKey::setG(const ByteString& inG)
{
	DSAPublicKey::setG(inG);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

void OSSLDSAPublicKey::setY(const ByteString& inY)
{
	DSAPublicKey::setY(inY);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLDSAPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLDSAPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_q = OSSL::byteString2bn(q);
	BIGNUM* bn_g = OSSL::byteString2bn(g);
	BIGNUM* bn_pub_key = OSSL::byteString2bn(y);

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM* params = NULL;
	EVP_PKEY_CTX* ctx = NULL;

	if (bld == NULL ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, bn_q) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bn_pub_key) ||
	    (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
	    (ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL)) == NULL ||
	    EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	{
		ERROR_MSG("Could not create the DSA public key");

		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(bn_p);
	BN_free(bn_q);
	BN_free(bn_g);
	BN_free(bn_pub_key);
}
