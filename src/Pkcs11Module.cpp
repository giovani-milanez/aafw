/*
 * Pkcs11Module.cpp
 *
 *  Created on: 14/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/Pkcs11Module.hpp"
#include "aafw/Exception.hpp"

namespace aafw {

Pkcs11Module::Pkcs11Module(const std::string& moduleLocation) :
		lib_(),
		funcs_(nullptr),
		mustFinalize_(true)
{
	bool unloadOnError = true;
	try {
		lib_.load(moduleLocation);
	}catch(const Poco::LibraryAlreadyLoadedException& e){
		// Thats ok
		unloadOnError = false;
	}catch(const Poco::LibraryLoadException& e){
		throw cryptobase::LibraryLoadException(e.message());
	}

	CK_RV (*functionListPointer)(CK_FUNCTION_LIST_PTR_PTR) = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) lib_.getSymbol("C_GetFunctionList");
	CK_RV rv = functionListPointer(&funcs_);
	if(rv != CKR_OK)
	{
		if(unloadOnError)
			lib_.unload();
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);
	}

	rv = funcs_->C_Initialize(nullptr);
	if(rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		if(unloadOnError)
			lib_.unload();
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);
	}
	mustFinalize_ = rv != CKR_CRYPTOKI_ALREADY_INITIALIZED;
}

Pkcs11Module::~Pkcs11Module()
{
	if(mustFinalize_)
	{
		funcs_->C_Finalize(nullptr);
		lib_.unload();
	}
}

Pkcs11Session Pkcs11Module::openSession(CK_SLOT_ID slotId, const std::string& pin)
{
	return Pkcs11Session(funcs_, slotId, pin);
}

Pkcs11Session Pkcs11Module::openSession(const std::string& slotLabel, const std::string& pin)
{
	return Pkcs11Session(funcs_, findTokenFromName(slotLabel), pin);
}

CK_SLOT_ID Pkcs11Module::findTokenFromName(const std::string& label)
{
	CK_SLOT_ID toReturn;
	bool found = false;
	CK_ULONG pulCount = 0;
	std::vector<CK_SLOT_ID> slotList;
	std::string labelPkcs11(label);
	labelPkcs11.resize(32, ' '); // 32 is the size of padded label that pkcs11 supports
	const char *toCompare = labelPkcs11.c_str();

	CK_RV rv = funcs_->C_GetSlotList(CK_TRUE, nullptr, &pulCount);
	if (rv != CKR_OK)
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);

	slotList.resize(pulCount);
	rv = funcs_->C_GetSlotList(CK_TRUE, slotList.data(), &pulCount);
	if (rv != CKR_OK)
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);

	for (auto i : slotList)
	{
		CK_TOKEN_INFO tokenInfo;
		rv = funcs_->C_GetTokenInfo(i, &tokenInfo);
		if (rv != CKR_OK)
			throw Pkcs11Exception(pkcs11Error2Message(rv), rv);

		if (memcmp(tokenInfo.label, toCompare, 32) == 0){
			toReturn = i;
			found = true;
			break;
		}
	}
	if (!found)
		throw cryptobase::NotFoundException("Token ID of label "+label+" not found.");

	return toReturn;
}

} /* namespace aafw */
