/*****************************************************************************
 MLKEMParameters.cpp

 ML-KEM parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLKEMParameters.h"
#include <string.h>

// The type
/*static*/ const char* MLKEMParameters::type = "ML-KEM parameters";

// Set the parameter set
void MLKEMParameters::setParameterSet(const unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the parameter set
unsigned long MLKEMParameters::getParameterSet() const
{
	return parameterSet;
}

// Are the parameters of the given type?
bool MLKEMParameters::areOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

// Serialisation
ByteString MLKEMParameters::serialise() const
{
	return ByteString(getParameterSet());
}

bool MLKEMParameters::deserialise(ByteString& serialised)
{

	if (serialised.size() == 0)
	{
		return false;
	}

	setParameterSet(serialised.long_val());

	return true;
}

