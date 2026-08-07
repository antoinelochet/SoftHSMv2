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
 OSSLECPrivateKey.cpp

 OpenSSL EC private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <string.h>

// Constructors
OSSLECPrivateKey::OSSLECPrivateKey()
{
	pkey = NULL;
}

OSSLECPrivateKey::OSSLECPrivateKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLECPrivateKey::~OSSLECPrivateKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLECPrivateKey::type = "OpenSSL EC Private Key";

// Get the base point order length
unsigned long OSSLECPrivateKey::getOrderLength() const
{
	EC_GROUP* grp = OSSL::byteString2grp(ec);
	if (grp == NULL) return 0;

	unsigned long len = 0;
	BIGNUM* order = BN_new();
	if (order != NULL && EC_GROUP_get_order(grp, order, NULL))
	{
		len = BN_num_bytes(order);
	}

	BN_clear_free(order);
	EC_GROUP_free(grp);

	return len;
}

// Set from OpenSSL representation
void OSSLECPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	// For EC keys this yields the ECPKParameters encoding, named or explicit
	unsigned char* der = NULL;
	int derLen = i2d_KeyParams(inPKEY, &der);
	if (derLen > 0)
	{
		ByteString inEC(der, derLen);
		OPENSSL_free(der);
		setEC(inEC);
	}

	BIGNUM* bn_d = NULL;
	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_PRIV_KEY, &bn_d))
	{
		ByteString inD = OSSL::bn2ByteString(bn_d);
		setD(inD);
		BN_clear_free(bn_d);
	}
}

// Check if the key is of the given type
bool OSSLECPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EC private key components
void OSSLECPrivateKey::setD(const ByteString& inD)
{
	ECPrivateKey::setD(inD);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}


// Setters for the EC public key components
void OSSLECPrivateKey::setEC(const ByteString& inEC)
{
	ECPrivateKey::setEC(inEC);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

// Encode into PKCS#8 DER
ByteString OSSLECPrivateKey::PKCS8Encode()
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
bool OSSLECPrivateKey::PKCS8Decode(const ByteString& ber)
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
EVP_PKEY* OSSLECPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLECPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;

	pkey = OSSL::ec2PKey(ec, NULL, &d);
}
#endif
