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
 SLHDSAParameters.h

 SLH-DSA parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSAPARAMETERS_H
#define _SOFTHSM_V2_SLHDSAPARAMETERS_H

#include "config.h"
#include "ByteString.h"
#include "AsymmetricParameters.h"


class SLHDSAParameters : public AsymmetricParameters
{
public:
	/** \brief Constructor */
	SLHDSAParameters();

	/** \brief The type */
	static const char* type;

	/** \brief Get the SLH-DSA parameter set */
	virtual unsigned long getParameterSet() const;

	/** \brief Setters for the SLH-DSA parameter set */
	virtual void setParameterSet(const unsigned long parameterSet);

	/** \brief Are the parameters of the given type? */
	virtual bool areOfType(const char* inType);

	/** \brief Serialisation */
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// Centralized helpers for parameter set support and signature length
	static bool isSupported(const unsigned long parameterSet);
	static unsigned long signatureLength(const unsigned long parameterSet);



	/* SLH-DSA values for CKA_PARAMETER_SETS */
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_128S_PARAMETER_SET = CKP_SLH_DSA_SHA2_128S;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_128S_PARAMETER_SET = CKP_SLH_DSA_SHAKE_128S;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_128F_PARAMETER_SET = CKP_SLH_DSA_SHA2_128F;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_128F_PARAMETER_SET = CKP_SLH_DSA_SHAKE_128F;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_192S_PARAMETER_SET = CKP_SLH_DSA_SHA2_192S;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_192S_PARAMETER_SET = CKP_SLH_DSA_SHAKE_192S;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_192F_PARAMETER_SET = CKP_SLH_DSA_SHA2_192F;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_192F_PARAMETER_SET = CKP_SLH_DSA_SHAKE_192F;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_256S_PARAMETER_SET = CKP_SLH_DSA_SHA2_256S;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_256S_PARAMETER_SET = CKP_SLH_DSA_SHAKE_256S;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_256F_PARAMETER_SET = CKP_SLH_DSA_SHA2_256F;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_256F_PARAMETER_SET = CKP_SLH_DSA_SHAKE_256F;

	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_128S_PRIV_LENGTH = 64;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_128S_PRIV_LENGTH = 64;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_128F_PRIV_LENGTH = 64;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_128F_PRIV_LENGTH = 64;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_192S_PRIV_LENGTH = 96;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_192S_PRIV_LENGTH = 96;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_192F_PRIV_LENGTH = 96;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_192F_PRIV_LENGTH = 96;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_256S_PRIV_LENGTH = 128;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_256S_PRIV_LENGTH = 128;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_256F_PRIV_LENGTH = 128;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_256F_PRIV_LENGTH = 128;

	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_128S_PUB_LENGTH = 32;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_128S_PUB_LENGTH = 32;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_128F_PUB_LENGTH = 32;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_128F_PUB_LENGTH = 32;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_192S_PUB_LENGTH = 48;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_192S_PUB_LENGTH = 48;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_192F_PUB_LENGTH = 48;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_192F_PUB_LENGTH = 48;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_256S_PUB_LENGTH = 64;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_256S_PUB_LENGTH = 64;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_256F_PUB_LENGTH = 64;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_256F_PUB_LENGTH = 64;

	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_128S_SIGNATURE_LENGTH = 7856;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_128S_SIGNATURE_LENGTH = 7856;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_128F_SIGNATURE_LENGTH = 17088;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_128F_SIGNATURE_LENGTH = 17088;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_192S_SIGNATURE_LENGTH = 16224;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_192S_SIGNATURE_LENGTH = 16224;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_192F_SIGNATURE_LENGTH = 35664;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_192F_SIGNATURE_LENGTH = 35664;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_256S_SIGNATURE_LENGTH = 29792;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_256S_SIGNATURE_LENGTH = 29792;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHA2_256F_SIGNATURE_LENGTH = 49856;
	/** \brief SLH-DSA constant */
	static const unsigned long SLH_DSA_SHAKE_256F_SIGNATURE_LENGTH = 49856;



private:
	/** \brief The parameter set */
	unsigned long parameterSet;

};

#endif // !_SOFTHSM_V2_SLHDSAPARAMETERS_H

