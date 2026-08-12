/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 BotanCompat.h

 Compatibility layer that hides the API differences between Botan 2 and
 Botan 3. Botan 3 turned most of the loose ASN.1/EC/DL enumerations into
 scoped enumerations, moved several headers around and replaced a number of
 public data members by accessor functions.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANCOMPAT_H
#define _SOFTHSM_V2_BOTANCOMPAT_H

#include "config.h"
#include <botan/version.h>

#if BOTAN_VERSION_MAJOR >= 3
#include <botan/asn1_obj.h>
#include <botan/bigint.h>
#include <botan/cipher_mode.h>
#include <botan/dl_group.h>
#else
#include <botan/asn1_obj.h>
#include <botan/asn1_oid.h>
#include <botan/bigint.h>
#include <botan/cipher_mode.h>
#include <botan/dl_group.h>
#include <botan/oids.h>
#endif

#if defined(WITH_ECC) || defined(WITH_GOST)
#include <botan/ec_group.h>
#endif

// Botan 3 dropped the "SHA-160" alias for SHA-1
#if BOTAN_VERSION_MAJOR >= 3
#define BOTAN_COMPAT_SHA1 "SHA-1"
#else
#define BOTAN_COMPAT_SHA1 "SHA-160"
#endif

#include <string>

namespace BotanCompat
{
#if BOTAN_VERSION_MAJOR >= 3
	typedef Botan::ASN1_Type Asn1Type;
	typedef Botan::ASN1_Class Asn1Class;
	typedef Botan::DL_Group_Format DLGroupFormat;

	static const Asn1Class UNIVERSAL	= Botan::ASN1_Class::Universal;
	static const Asn1Type SEQUENCE		= Botan::ASN1_Type::Sequence;
	static const Asn1Type OCTET_STRING	= Botan::ASN1_Type::OctetString;
	static const Asn1Type PRINTABLE_STRING	= Botan::ASN1_Type::PrintableString;
	static const Asn1Type OBJECT_ID		= Botan::ASN1_Type::ObjectId;

	static const DLGroupFormat PKCS3_DH_PARAMETERS	= Botan::DL_Group_Format::PKCS3_DH_PARAMETERS;

	static const Botan::Cipher_Dir ENCRYPTION = Botan::Cipher_Dir::Encryption;
	static const Botan::Cipher_Dir DECRYPTION = Botan::Cipher_Dir::Decryption;

#if defined(WITH_ECC) || defined(WITH_GOST)
	static const Botan::EC_Group_Encoding EC_DOMPAR_ENC_OID = Botan::EC_Group_Encoding::NamedCurve;
	static const Botan::EC_Point_Format EC_POINT_UNCOMPRESSED = Botan::EC_Point_Format::Uncompressed;
#endif

	// True when the BER object carries the given universal tag
	inline bool isA(const Botan::BER_Object& object, Asn1Type type)
	{
		return object.is_a(type, UNIVERSAL);
	}

	inline const Botan::OID& algIdOid(const Botan::AlgorithmIdentifier& algId)
	{
		return algId.oid();
	}

	inline Botan::OID str2Oid(const std::string& name)
	{
		return Botan::OID::from_string(name);
	}

	inline std::string oid2Str(const Botan::OID& oid)
	{
		return oid.human_name_or_empty();
	}

	// Botan 3 replaced the per-scheme DL accessors by a generic field lookup
	template <typename K> const Botan::BigInt& groupP(const K& key) { return key.get_int_field("p"); }
	template <typename K> const Botan::BigInt& groupQ(const K& key) { return key.get_int_field("q"); }
	template <typename K> const Botan::BigInt& groupG(const K& key) { return key.get_int_field("g"); }
	template <typename K> const Botan::BigInt& getX(const K& key) { return key.get_int_field("x"); }
	template <typename K> const Botan::BigInt& getY(const K& key) { return key.get_int_field("y"); }
#else
	typedef Botan::ASN1_Tag Asn1Type;
	typedef Botan::ASN1_Tag Asn1Class;
	typedef Botan::DL_Group::Format DLGroupFormat;

	static const Asn1Class UNIVERSAL	= Botan::UNIVERSAL;
	static const Asn1Type SEQUENCE		= Botan::SEQUENCE;
	static const Asn1Type OCTET_STRING	= Botan::OCTET_STRING;
	static const Asn1Type PRINTABLE_STRING	= Botan::PRINTABLE_STRING;
	static const Asn1Type OBJECT_ID		= Botan::OBJECT_ID;

	static const DLGroupFormat PKCS3_DH_PARAMETERS	= Botan::DL_Group::PKCS3_DH_PARAMETERS;

	static const Botan::Cipher_Dir ENCRYPTION = Botan::ENCRYPTION;
	static const Botan::Cipher_Dir DECRYPTION = Botan::DECRYPTION;

#if defined(WITH_ECC) || defined(WITH_GOST)
	static const Botan::EC_Group_Encoding EC_DOMPAR_ENC_OID = Botan::EC_DOMPAR_ENC_OID;
	static const Botan::PointGFp::Compression_Type EC_POINT_UNCOMPRESSED = Botan::PointGFp::UNCOMPRESSED;
#endif

	inline bool isA(const Botan::BER_Object& object, Asn1Type type)
	{
		return object.is_a(type, UNIVERSAL);
	}

	inline const Botan::OID& algIdOid(const Botan::AlgorithmIdentifier& algId)
	{
		return algId.oid;
	}

	inline Botan::OID str2Oid(const std::string& name)
	{
		return Botan::OIDS::lookup(name);
	}

	inline std::string oid2Str(const Botan::OID& oid)
	{
		return Botan::OIDS::lookup(oid);
	}

	template <typename K> const Botan::BigInt& groupP(const K& key) { return key.group_p(); }
	template <typename K> const Botan::BigInt& groupQ(const K& key) { return key.group_q(); }
	template <typename K> const Botan::BigInt& groupG(const K& key) { return key.group_g(); }
	template <typename K> const Botan::BigInt& getX(const K& key) { return key.get_x(); }
	template <typename K> const Botan::BigInt& getY(const K& key) { return key.get_y(); }
#endif
}

#endif // !_SOFTHSM_V2_BOTANCOMPAT_H
