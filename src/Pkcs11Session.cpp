/*
 * Pkcs11Session.cpp
 *
 *  Created on: 14/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/Pkcs11Session.hpp"
#include "aafw/Exception.hpp"

#include <openssl/rsa.h>

namespace aafw {

Pkcs11Session::Pkcs11Session(CK_FUNCTION_LIST_PTR funcs, CK_SLOT_ID slot, const std::string& pin) :
		funcs_(funcs),
		slot_(slot),
		sessionHandle_(),
		loggedIn_(false)
{
	if(funcs_ == nullptr)
		throw cryptobase::NullPointerException("Null CK_FUNCTION_LIST_PTR");

	CK_RV rv = funcs_->C_OpenSession (slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &sessionHandle_);
	if(rv != CKR_OK)
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);

	if(!pin.empty())
		login(pin);
}

Pkcs11Session::~Pkcs11Session()
{
	if(loggedIn_)
		funcs_->C_Logout(sessionHandle_);

	funcs_->C_CloseSession(sessionHandle_);
}

void Pkcs11Session::login(const std::string& pin)
{
	if (loggedIn_)
		return;

	CK_RV rv = funcs_->C_Login(sessionHandle_, CKU_USER, (unsigned char *) pin.c_str(), pin.size());
	if(rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);
	loggedIn_ = true;
}

CK_OBJECT_HANDLE Pkcs11Session::findObject(const std::string& objLabel, CK_OBJECT_CLASS objClass)
{
	CK_RV rv;
    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;
    CK_ATTRIBUTE template_pkcs11[] = {
    		{ CKA_CLASS, &objClass, sizeof(objClass) },
    		{ CKA_LABEL, (char *)objLabel.c_str(), objLabel.size() }
    };
    rv = funcs_->C_FindObjectsInit(sessionHandle_, template_pkcs11, 2);
	if ( rv != CKR_OK )
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);

	rv = funcs_->C_FindObjects(sessionHandle_, &object, 1, &objectCount);
	if ( rv != CKR_OK )
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);

	rv = funcs_->C_FindObjectsFinal(sessionHandle_);
	if ( rv != CKR_OK )
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);

	if(objectCount > 0)
		return object;

	throw cryptobase::NotFoundException("Object "+objLabel+" not found");
}

cryptobase::PrivateKey Pkcs11Session::extractPkcs11Key(CK_OBJECT_HANDLE keyHandle)
{
	CK_BYTE_PTR modulus, public_exponent;
	CK_ULONG modulus_size, public_exponent_size;
	RSA *rsa;

	// Template to query for modulus and exponent
	CK_ATTRIBUTE tmpl[] = {
			{CKA_MODULUS, NULL_PTR, 0},
			{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
	};

	// Call once to get size
	CK_RV rv = funcs_->C_GetAttributeValue(sessionHandle_, keyHandle, tmpl, 2);
	if (rv != CKR_OK)
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);


	modulus_size = tmpl[0].ulValueLen; public_exponent_size = tmpl[1].ulValueLen;
	modulus = (CK_BYTE_PTR)malloc(modulus_size * sizeof(CK_BYTE));
	public_exponent = (CK_BYTE_PTR)malloc(public_exponent_size * sizeof(CK_BYTE));
	tmpl[0].pValue = modulus; tmpl[1].pValue = public_exponent;

	// Call again to get values
	rv = funcs_->C_GetAttributeValue(sessionHandle_, keyHandle, tmpl, 2);
	if (rv != CKR_OK){
		free(modulus);
		free(public_exponent);
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);
	}

	if(rsaIdx == -1)
		rsaIdx = RSA_get_ex_new_index(0, nullptr, nullptr, nullptr, 0);
	rsa = RSA_new();
	rsa->n = BN_bin2bn(modulus, modulus_size, nullptr);
	rsa->e = BN_bin2bn(public_exponent, public_exponent_size, nullptr);
	RSA_set_method(rsa, getRsaMethod());
	rsa->flags |= RSA_FLAG_SIGN_VER;

	KeyCtx ctx;
	ctx.funcs_ = funcs_;
	ctx.sessionHandle_ = sessionHandle_;
	ctx.keyHandle_ = keyHandle;

	ctxs_.push_back(ctx);

	RSA_set_ex_data(rsa, rsaIdx, (void *)&ctxs_.back());

	cryptobase::PrivateKey priv(rsa);

	free(modulus); free(public_exponent);
	return priv;
}

cryptobase::Certificate Pkcs11Session::extractCertificate(CK_OBJECT_HANDLE certHandle)
{
	CK_ATTRIBUTE tmpl[] = {
			{CKA_VALUE, NULL_PTR, 0}
	};

	CK_RV rv = funcs_->C_GetAttributeValue(sessionHandle_, certHandle, tmpl, 1);
	if (rv != CKR_OK)
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);


	tmpl[0].pValue = (CK_BYTE_PTR)malloc(tmpl[0].ulValueLen * sizeof(CK_BYTE));

	rv = funcs_->C_GetAttributeValue(sessionHandle_, certHandle, tmpl, 1);
	if (rv != CKR_OK){
		throw Pkcs11Exception(pkcs11Error2Message(rv), rv);
	}

	cryptobase::ByteArray certDer((const unsigned char *)tmpl[0].pValue, tmpl[0].ulValueLen); // makes a copy
	free(tmpl[0].pValue);
	return cryptobase::Certificate(certDer);
}

} /* namespace aafw */
