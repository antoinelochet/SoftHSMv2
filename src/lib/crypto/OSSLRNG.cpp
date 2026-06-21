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
 OSSLRNG.cpp

 OpenSSL random number generator class
 *****************************************************************************/

#include "config.h"
#include "OSSLRNG.h"
#include <openssl/rand.h>
#include <limits.h>

// RAND_bytes()/RAND_seed() take an int length, so a size_t over INT_MAX would
// be truncated. Clamp each call and loop so the whole request is covered.
static int clampToInt(size_t len)
{
	return len > (size_t) INT_MAX ? INT_MAX : (int) len;
}

// Generate random data
bool OSSLRNG::generateRandom(ByteString& data, const size_t len)
{
	data.wipe(len);

	size_t offset = 0;
	while (offset < len)
	{
		int chunk = clampToInt(len - offset);
		if (RAND_bytes(&data[offset], chunk) != 1)
			return false;
		offset += (size_t) chunk;
	}
	return true;
}

// Seed the random pool
void OSSLRNG::seed(ByteString& seedData)
{
	// RAND_seed() accumulates entropy, so feeding the seed in pieces is fine.
	const unsigned char* bytes = seedData.const_byte_str();
	size_t len = seedData.size();

	size_t offset = 0;
	while (offset < len)
	{
		int chunk = clampToInt(len - offset);
		RAND_seed(bytes + offset, chunk);
		offset += (size_t) chunk;
	}
}

