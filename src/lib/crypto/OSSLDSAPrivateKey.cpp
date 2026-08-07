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
 OSSLDSAPrivateKey.cpp

 OpenSSL DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDSAPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <string.h>

// Constructors
OSSLDSAPrivateKey::OSSLDSAPrivateKey()
{
	pkey = NULL;
}

OSSLDSAPrivateKey::OSSLDSAPrivateKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLDSAPrivateKey::~OSSLDSAPrivateKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLDSAPrivateKey::type = "OpenSSL DSA Private Key";

// Set from OpenSSL representation
void OSSLDSAPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	BIGNUM* bn_p = NULL;
	BIGNUM* bn_q = NULL;
	BIGNUM* bn_g = NULL;
	BIGNUM* bn_priv_key = NULL;

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
	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv_key))
	{
		ByteString inX = OSSL::bn2ByteString(bn_priv_key);
		setX(inX);
		BN_clear_free(bn_priv_key);
	}
}

// Check if the key is of the given type
bool OSSLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DSA private key components
void OSSLDSAPrivateKey::setX(const ByteString& inX)
{
	DSAPrivateKey::setX(inX);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}


// Setters for the DSA domain parameters
void OSSLDSAPrivateKey::setP(const ByteString& inP)
{
	DSAPrivateKey::setP(inP);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

void OSSLDSAPrivateKey::setQ(const ByteString& inQ)
{
	DSAPrivateKey::setQ(inQ);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

void OSSLDSAPrivateKey::setG(const ByteString& inG)
{
	DSAPrivateKey::setG(inG);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

// Encode into PKCS#8 DER
ByteString OSSLDSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	createOSSLKey();
	if (pkey == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(pkey);
	if (p8inf == NULL) return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char* priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len) der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLDSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* key = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (key == NULL) return false;
	setFromOSSL(key);
	EVP_PKEY_free(key);
	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLDSAPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLDSAPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_q = OSSL::byteString2bn(q);
	BIGNUM* bn_g = OSSL::byteString2bn(g);
	BIGNUM* bn_priv_key = OSSL::byteString2bn(x);
	BIGNUM* bn_pub_key = BN_new();
	BN_CTX* ctx = BN_CTX_new();

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM* params = NULL;
	EVP_PKEY_CTX* pctx = NULL;

	// OpenSSL requires the public key alongside the private one
	if (ctx == NULL || bn_pub_key == NULL ||
	    !BN_mod_exp(bn_pub_key, bn_g, bn_priv_key, bn_p, ctx) ||
	    bld == NULL ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, bn_q) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bn_pub_key) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv_key) ||
	    (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
	    (pctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL)) == NULL ||
	    EVP_PKEY_fromdata_init(pctx) <= 0 ||
	    EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
	{
		ERROR_MSG("Could not create the DSA private key");

		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(pctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_CTX_free(ctx);
	BN_free(bn_p);
	BN_free(bn_q);
	BN_free(bn_g);
	BN_free(bn_pub_key);
	BN_clear_free(bn_priv_key);
}
