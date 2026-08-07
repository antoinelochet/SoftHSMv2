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
 OSSLECPublicKey.cpp

 OpenSSL Elliptic Curve public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "DerUtil.h"
#include "OSSLECPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <string.h>

// Constructors
OSSLECPublicKey::OSSLECPublicKey()
{
	pkey = NULL;
}

OSSLECPublicKey::OSSLECPublicKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLECPublicKey::~OSSLECPublicKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLECPublicKey::type = "OpenSSL EC Public Key";

// Get the base point order length
unsigned long OSSLECPublicKey::getOrderLength() const
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
void OSSLECPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	// For EC keys this yields the ECPKParameters encoding, named or explicit
	unsigned char* der = NULL;
	int derLen = i2d_KeyParams(inPKEY, &der);
	if (derLen <= 0) return;

	ByteString inEC(der, derLen);
	OPENSSL_free(der);
	setEC(inEC);

	EC_GROUP* grp = OSSL::byteString2grp(inEC);
	if (grp == NULL) return;

	size_t pubLen = 0;
	if (EVP_PKEY_get_octet_string_param(inPKEY, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubLen) &&
	    pubLen != 0)
	{
		ByteString raw;
		raw.resize(pubLen);

		EC_POINT* pt = EC_POINT_new(grp);
		if (pt != NULL &&
		    EVP_PKEY_get_octet_string_param(inPKEY, OSSL_PKEY_PARAM_PUB_KEY, &raw[0], pubLen, &pubLen) &&
		    EC_POINT_oct2point(grp, pt, &raw[0], pubLen, NULL))
		{
			// Normalise to the uncompressed form used for storage
			ByteString inQ = OSSL::pt2ByteString(pt, grp);
			setQ(inQ);
		}
		EC_POINT_free(pt);
	}

	EC_GROUP_free(grp);
}

// Check if the key is of the given type
bool OSSLECPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EC public key components
void OSSLECPublicKey::setEC(const ByteString& inEC)
{
	ECPublicKey::setEC(inEC);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

void OSSLECPublicKey::setQ(const ByteString& inQ)
{
	ECPublicKey::setQ(inQ);

	EVP_PKEY_free(pkey);
	pkey = NULL;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLECPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLECPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;

	pkey = OSSL::ec2PKey(ec, &q, NULL);
}
#endif
