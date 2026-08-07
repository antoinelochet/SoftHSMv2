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
 OSSLUtil.h

 OpenSSL convenience functions
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "DerUtil.h"
#include "OSSLUtil.h"
#if defined(WITH_ML_DSA) || defined(WITH_ML_KEM)
#include <map>
#endif
#ifdef WITH_ML_DSA
#include "MLDSAParameters.h"
#endif
#ifdef WITH_ML_KEM
#include "MLKEMParameters.h"
#endif
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef WITH_ECC
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/objects.h>
#endif

#ifdef WITH_ML_DSA
static const std::map<unsigned long, const char*> mldsaAlgNameFromParameterSet {
	{MLDSAParameters::ML_DSA_44_PARAMETER_SET, "ML-DSA-44"},
	{MLDSAParameters::ML_DSA_65_PARAMETER_SET, "ML-DSA-65"},
	{MLDSAParameters::ML_DSA_87_PARAMETER_SET, "ML-DSA-87"}
};
#endif

#ifdef WITH_ML_KEM
static const std::map<unsigned long, const char*> mlkemAlgNameFromParameterSet {
	{MLKEMParameters::ML_KEM_512_PARAMETER_SET, "ML-KEM-512"},
	{MLKEMParameters::ML_KEM_768_PARAMETER_SET, "ML-KEM-768"},
	{MLKEMParameters::ML_KEM_1024_PARAMETER_SET, "ML-KEM-1024"}
};
#endif

// Convert an OpenSSL BIGNUM to a ByteString
ByteString OSSL::bn2ByteString(const BIGNUM* bn)
{
	ByteString rv;

	if (bn != NULL)
	{
		rv.resize(BN_num_bytes(bn));
		BN_bn2bin(bn, &rv[0]);
	}

	return rv;
}

// Convert a ByteString to an OpenSSL BIGNUM
BIGNUM* OSSL::byteString2bn(const ByteString& byteString)
{
	if (byteString.size() == 0) return NULL;

	return BN_bin2bn(byteString.const_byte_str(), byteString.size(), NULL);
}

#ifdef WITH_ECC
// Convert an OpenSSL EC GROUP to a ByteString
ByteString OSSL::grp2ByteString(const EC_GROUP* grp)
{
	ByteString rv;

	if (grp != NULL)
	{
		rv.resize(i2d_ECPKParameters(grp, NULL));
		unsigned char *p = &rv[0];
		i2d_ECPKParameters(grp, &p);
	}

	return rv;
}

// Convert a ByteString to an OpenSSL EC GROUP
EC_GROUP* OSSL::byteString2grp(const ByteString& byteString)
{
	const unsigned char *p = byteString.const_byte_str();
	return d2i_ECPKParameters(NULL, &p, byteString.size());
}

// POINT_CONVERSION_UNCOMPRESSED		0x04

// Convert an OpenSSL EC POINT in the given EC GROUP to a ByteString
ByteString OSSL::pt2ByteString(const EC_POINT* pt, const EC_GROUP* grp)
{
	ByteString raw;

	if (pt == NULL || grp == NULL)
		return raw;

	size_t len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	raw.resize(len);
	EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, &raw[0], len, NULL);

	return DERUTIL::raw2Octet(raw);
}

// Convert a ByteString to an OpenSSL EC POINT in the given EC GROUP
EC_POINT* OSSL::byteString2pt(const ByteString& byteString, const EC_GROUP* grp)
{
	ByteString raw = DERUTIL::octet2Raw(byteString);
	size_t len = raw.size();
	if (len == 0) return NULL;

	EC_POINT* pt = EC_POINT_new(grp);
	if (!EC_POINT_oct2point(grp, pt, &raw[0], len, NULL))
	{
		ERROR_MSG("EC_POINT_oct2point failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_POINT_free(pt);
		return NULL;
	}
	return pt;
}

// Describe an EC group as OSSL_PARAMs, by name where possible and explicitly otherwise.
// The BIGNUMs and octets pushed here must outlive OSSL_PARAM_BLD_to_param().
static bool ecGroup2Params(const EC_GROUP* grp, OSSL_PARAM_BLD* bld, BN_CTX* bnctx,
			   BIGNUM* bn_p, BIGNUM* bn_a, BIGNUM* bn_b, ByteString& genOct)
{
	int nid = EC_GROUP_get_curve_name(grp);

	// Explicit parameters that match a built-in curve still get a curve name from
	// d2i_ECPKParameters, so the ASN.1 flag is what tells the two encodings apart
	if (nid != NID_undef && EC_GROUP_get_asn1_flag(grp) == OPENSSL_EC_NAMED_CURVE)
	{
		const char* name = OBJ_nid2sn(nid);

		return name != NULL &&
		       OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, name, 0) == 1;
	}

	const EC_POINT* gen = EC_GROUP_get0_generator(grp);
	const BIGNUM* order = EC_GROUP_get0_order(grp);
	const BIGNUM* cofactor = EC_GROUP_get0_cofactor(grp);
	const unsigned char* seed = EC_GROUP_get0_seed(grp);
	size_t seedLen = EC_GROUP_get_seed_len(grp);
	const char* fieldType = EC_GROUP_get_field_type(grp) == NID_X9_62_prime_field
				? "prime-field" : "characteristic-two-field";

	if (gen == NULL || order == NULL) return false;

	size_t genLen = EC_POINT_point2oct(grp, gen, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
	if (genLen == 0) return false;
	genOct.resize(genLen);
	if (EC_POINT_point2oct(grp, gen, POINT_CONVERSION_UNCOMPRESSED, &genOct[0], genLen, bnctx) == 0)
		return false;

	return EC_GROUP_get_curve(grp, bn_p, bn_a, bn_b, bnctx) &&
	       OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING,
					       OSSL_PKEY_EC_ENCODING_EXPLICIT, 0) &&
	       OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_FIELD_TYPE, fieldType, 0) &&
	       OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_P, bn_p) &&
	       OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_A, bn_a) &&
	       OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_B, bn_b) &&
	       OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_GENERATOR,
						&genOct[0], genOct.size()) &&
	       OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_ORDER, order) &&
	       (cofactor == NULL ||
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_COFACTOR, cofactor)) &&
	       // Informational only, but kept so the parameter encoding round-trips unchanged
	       (seed == NULL || seedLen == 0 ||
		OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_SEED, seed, seedLen));
}

// Build an EVP_PKEY from DER-encoded EC domain parameters and optional key material
EVP_PKEY* OSSL::ec2PKey(const ByteString& ec, const ByteString* q, const ByteString* d)
{
	EC_GROUP* grp = byteString2grp(ec);
	if (grp == NULL)
	{
		ERROR_MSG("Failed to decode the EC domain parameters");

		return NULL;
	}

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM* params = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;
	BN_CTX* bnctx = BN_CTX_new();
	BIGNUM* bn_p = BN_new();
	BIGNUM* bn_a = BN_new();
	BIGNUM* bn_b = BN_new();
	BIGNUM* bn_d = NULL;
	ByteString genOct;
	ByteString pubRaw;
	int selection = EVP_PKEY_KEY_PARAMETERS;

	bool ok = bld != NULL && bnctx != NULL && bn_p != NULL && bn_a != NULL && bn_b != NULL &&
		  ecGroup2Params(grp, bld, bnctx, bn_p, bn_a, bn_b, genOct);

	if (ok && d != NULL)
	{
		bn_d = byteString2bn(*d);
		ok = bn_d != NULL;
	}

	if (ok && q != NULL)
	{
		pubRaw = DERUTIL::octet2Raw(*q);
		ok = pubRaw.size() != 0;
	}
	else if (ok && bn_d != NULL)
	{
		// OpenSSL requires the public point alongside the private scalar
		EC_POINT* pub = EC_POINT_new(grp);
		size_t pubLen = 0;

		ok = pub != NULL && EC_POINT_mul(grp, pub, bn_d, NULL, NULL, bnctx) &&
		     (pubLen = EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
						  NULL, 0, bnctx)) != 0;
		if (ok)
		{
			pubRaw.resize(pubLen);
			ok = EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
						&pubRaw[0], pubLen, bnctx) != 0;
		}

		EC_POINT_free(pub);
	}

	if (ok && pubRaw.size() != 0)
	{
		ok = OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
						      &pubRaw[0], pubRaw.size()) == 1;
		selection = EVP_PKEY_PUBLIC_KEY;
	}

	if (ok && bn_d != NULL)
	{
		// Matches the historical EC_PKEY_NO_PUBKEY flag used for PKCS#8 encoding
		ok = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_d) &&
		     OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0);
		selection = EVP_PKEY_KEYPAIR;
	}

	if (!ok ||
	    (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
	    (ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL ||
	    EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0)
	{
		ERROR_MSG("Failed to create the EC key: %s", ERR_error_string(ERR_get_error(), NULL));

		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_CTX_free(bnctx);
	BN_free(bn_p);
	BN_free(bn_a);
	BN_free(bn_b);
	BN_clear_free(bn_d);
	EC_GROUP_free(grp);

	return pkey;
}
#endif

#ifdef WITH_EDDSA
// Convert an OpenSSL NID to a ByteString
ByteString OSSL::oid2ByteString(int nid)
{
	ByteString rv;
	std::string name;

	switch (nid)
	{
		case EVP_PKEY_ED25519:
			name = "edwards25519";
			break;

		case EVP_PKEY_X25519:
			name = "curve25519";
			break;

		case EVP_PKEY_ED448:
			name = "edwards448";
			break;

		case EVP_PKEY_X448:
			name = "curve448";
			break;

		default:
			return rv;
	}

	ASN1_PRINTABLESTRING *str = ASN1_PRINTABLESTRING_new();
	ASN1_STRING_set(str, name.c_str(), name.length());
	rv.resize(i2d_ASN1_PRINTABLESTRING(str, NULL));
	unsigned char *p = &rv[0];
	i2d_ASN1_PRINTABLESTRING(str, &p);
	ASN1_PRINTABLESTRING_free(str);

	return rv;
}

// Convert a ByteString to an OpenSSL EVP_PKEY id
int OSSL::byteString2oid(const ByteString& byteString)
{
	ASN1_OBJECT *oid;
	ASN1_PRINTABLESTRING *curve_name;
	const unsigned char *p = byteString.const_byte_str();
	const unsigned char *pp = p;
	const unsigned char *data;
	long length;
	int tag, pclass, data_len;
	int nid = NID_undef;

	ASN1_get_object(&pp, &length, &tag, &pclass, byteString.size());
	if (pclass == V_ASN1_UNIVERSAL && tag == V_ASN1_OBJECT)
	{
		/* The initial release of SoftHSM was expecting just OID value */
		oid = d2i_ASN1_OBJECT(NULL, &p, byteString.size());

		if (oid == NULL)
		{
			return NID_undef;
		}

		nid = OBJ_obj2nid(oid);
		ASN1_OBJECT_free(oid);
	}
	else if (pclass == V_ASN1_UNIVERSAL && tag == V_ASN1_PRINTABLESTRING)
	{
		/* The final PKCS#11 3.0 expects curve name encoded as PrintableString */
		curve_name = d2i_ASN1_PRINTABLESTRING(NULL, &p, byteString.size());

		if (curve_name == NULL)
		{
			return NID_undef;
		}

		data = ASN1_STRING_get0_data(curve_name);
		data_len = ASN1_STRING_length(curve_name);

		if (data_len == 12 && memcmp(data, "edwards25519", data_len) == 0)
		{
			ASN1_PRINTABLESTRING_free(curve_name);
			return EVP_PKEY_ED25519;
		}

		if (data_len == 10 && memcmp(data, "curve25519", 10) == 0)
		{
			ASN1_PRINTABLESTRING_free(curve_name);
			return EVP_PKEY_X25519;
		}

		if (data_len == 10 && memcmp(data, "edwards448", 10) == 0)
		{
			ASN1_PRINTABLESTRING_free(curve_name);
			return EVP_PKEY_ED448;
		}

		if (data_len == 8 && memcmp(data, "curve448", 8) == 0)
		{
			ASN1_PRINTABLESTRING_free(curve_name);
			return EVP_PKEY_X448;
		}

		ASN1_PRINTABLESTRING_free(curve_name);
	}

	return nid;
}
#endif

#ifdef WITH_ML_DSA
const char* OSSL::mldsaParameterSet2Name(unsigned long parameterSet) {

	std::map<unsigned long, const char*>::const_iterator it = mldsaAlgNameFromParameterSet.find(parameterSet);

	if (it != mldsaAlgNameFromParameterSet.end()) {
		return it->second;
	}

	return NULL;
}
#endif

#ifdef WITH_ML_KEM
const char* OSSL::mlkemParameterSet2Name(unsigned long parameterSet) {

	std::map<unsigned long, const char*>::const_iterator it = mlkemAlgNameFromParameterSet.find(parameterSet);

	if (it != mlkemAlgNameFromParameterSet.end()) {
		return it->second;
	}

	return NULL;
}
#endif
