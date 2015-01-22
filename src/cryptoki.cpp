/*
 * cryptoki.cpp
 *
 *  Created on: 14/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/pkcs11/cryptoki.h"
#include "cryptobase/ByteArray.hpp"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <iostream>

int rsaIdx = -1;

int freeRsaExData(RSA *r)
{
	return TRUE;
}
int rsaSign(int type, const unsigned char *m, unsigned int m_len,
			unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
	KeyCtx *keyCtx = (KeyCtx *) RSA_get_ex_data(rsa, rsaIdx);

	CK_RV rv;
	int ssl = ((type == NID_md5_sha1) ? 1 : 0);
	static CK_MECHANISM sign_mechanism = {CKM_RSA_PKCS, NULL, 0};
	unsigned char *encoded = nullptr;
	unsigned int sigsize = RSA_size(rsa);

	if (ssl) {
		if((m_len != 36) /* SHA1 + MD5 */ ||
		   ((m_len + RSA_PKCS1_PADDING_SIZE) > sigsize)) {
			return FALSE; /* the size is wrong */
		}
	} else {
		ASN1_TYPE parameter = { V_ASN1_NULL, { NULL } };
		ASN1_STRING digest = { (int) m_len, V_ASN1_OCTET_STRING, (unsigned char *)m };
		X509_ALGOR algor = { NULL, &parameter };
		X509_SIG digest_info = { &algor, &digest };
		unsigned int size;
		/* Fetch the OID of the algorithm used */
		if((algor.algorithm = OBJ_nid2obj(type)) &&
				(algor.algorithm->length) &&
				/* Get the size of the encoded DigestInfo */
				(size = i2d_X509_SIG(&digest_info, NULL)) &&
				/* Check that size is compatible with PKCS#11 padding */
				(size + RSA_PKCS1_PADDING_SIZE <= sigsize) &&
				(encoded = (unsigned char *) malloc(sigsize))) {
			unsigned char *tmp = encoded;
			/* Actually do the encoding */
			i2d_X509_SIG(&digest_info,&tmp);
			m = encoded;
			m_len = size;
		} else {
			return FALSE;
		}
	}

	CK_ULONG tmp = 0;
	// Enviando para o PKCS#11 assinar
	rv = keyCtx->funcs_->C_SignInit(keyCtx->sessionHandle_, &sign_mechanism, keyCtx->keyHandle_);
	if (rv != CKR_OK){
		goto err0;
	}

	if (sigret != NULL){
		tmp = RSA_size(rsa);
	}

	rv = keyCtx->funcs_->C_Sign(keyCtx->sessionHandle_, (unsigned char *)m, m_len, sigret, &tmp);
	if (rv != CKR_OK){
		goto err0;
	}

	*siglen = tmp;

	if (encoded) free(encoded); // NULL on ssl case
	return TRUE;
	err0:
	if (encoded) free(encoded); // NULL on ssl case
	std::cout << pkcs11Error2Message(rv) << std::endl;
	return FALSE;
}

RSA_METHOD *getRsaMethod()
{
	static RSA_METHOD ops;

	if (!ops.rsa_sign) {
		ops = *RSA_get_default_method();
		ops.rsa_sign = &rsaSign;
		ops.finish = freeRsaExData;
	}
	return &ops;
}

std::string pkcs11Error2Message(CK_RV code)
{
	std::string desc;
	switch (code) {
	case CKR_CANCEL:
			desc =  "CKR_CANCEL";break;
	case CKR_HOST_MEMORY:
			desc =  "CKR_HOST_MEMORY";break;
	case CKR_SLOT_ID_INVALID:
			desc =  "CKR_SLOT_ID_INVALID";break;
	case CKR_GENERAL_ERROR:
			desc =  "CKR_GENERAL_ERROR";break;
	case CKR_FUNCTION_FAILED:
			desc =  "CKR_FUNCTION_FAILED";break;
	case CKR_ARGUMENTS_BAD:
			desc =  "CKR_ARGUMENTS_BAD";break;
	case CKR_NO_EVENT:
			desc =  "CKR_NO_EVENT";break;
	case CKR_NEED_TO_CREATE_THREADS:
			desc =  "CKR_NEED_TO_CREATE_THREADS";break;
	case CKR_CANT_LOCK:
			desc =  "CKR_CANT_LOCK";break;
	case CKR_ATTRIBUTE_READ_ONLY:
			desc =  "CKR_ATTRIBUTE_READ_ONLY";break;
	case CKR_ATTRIBUTE_SENSITIVE:
			desc =  "CKR_ATTRIBUTE_SENSITIVE";break;
	case CKR_ATTRIBUTE_TYPE_INVALID:
			desc =  "CKR_ATTRIBUTE_TYPE_INVALID";break;
	case CKR_ATTRIBUTE_VALUE_INVALID:
			desc =  "CKR_ATTRIBUTE_VALUE_INVALID";break;
	case CKR_DATA_INVALID:
			desc =  "CKR_DATA_INVALID";break;
	case CKR_DATA_LEN_RANGE:
			desc =  "CKR_DATA_LEN_RANGE";break;
	case CKR_DEVICE_ERROR:
			desc =  "CKR_DEVICE_ERROR";break;
	case CKR_DEVICE_MEMORY:
			desc =  "CKR_DEVICE_MEMORY";break;
	case CKR_DEVICE_REMOVED:
			desc =  "CKR_DEVICE_REMOVED";break;
	case CKR_ENCRYPTED_DATA_INVALID:
			desc =  "CKR_ENCRYPTED_DATA_INVALID";break;
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
			desc =  "CKR_ENCRYPTED_DATA_LEN_RANGE";break;
	case CKR_FUNCTION_CANCELED:
			desc =  "CKR_FUNCTION_CANCELED";break;
	case CKR_FUNCTION_NOT_PARALLEL:
			desc =  "CKR_FUNCTION_NOT_PARALLEL";break;
	case CKR_FUNCTION_NOT_SUPPORTED:
			desc =  "CKR_FUNCTION_NOT_SUPPORTED";break;
	case CKR_KEY_HANDLE_INVALID:
			desc =  "CKR_KEY_HANDLE_INVALID";break;
	case CKR_KEY_SIZE_RANGE:
			desc =  "CKR_KEY_SIZE_RANGE";break;
	case CKR_KEY_TYPE_INCONSISTENT:
			desc =  "CKR_KEY_TYPE_INCONSISTENT";break;
	case CKR_KEY_NOT_NEEDED:
			desc =  "CKR_KEY_NOT_NEEDED";break;
	case CKR_KEY_CHANGED:
			desc =  "CKR_KEY_CHANGED";break;
	case CKR_KEY_NEEDED:
			desc =  "CKR_KEY_NEEDED";break;
	case CKR_KEY_INDIGESTIBLE:
			desc =  "CKR_KEY_INDIGESTIBLE";break;
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
			desc =  "CKR_KEY_FUNCTION_NOT_PERMITTED";break;
	case CKR_KEY_NOT_WRAPPABLE:
			desc =  "CKR_KEY_NOT_WRAPPABLE";break;
	case CKR_KEY_UNEXTRACTABLE:
			desc =  "CKR_KEY_UNEXTRACTABLE";break;
	case CKR_MECHANISM_INVALID:
			desc =  "CKR_MECHANISM_INVALID";break;
	case CKR_MECHANISM_PARAM_INVALID:
			desc =  "CKR_MECHANISM_PARAM_INVALID";break;
	case CKR_OBJECT_HANDLE_INVALID:
			desc =  "CKR_OBJECT_HANDLE_INVALID";break;
	case CKR_OPERATION_ACTIVE:
			desc =  "CKR_OPERATION_ACTIVE";break;
	case CKR_OPERATION_NOT_INITIALIZED:
			desc =  "CKR_OPERATION_NOT_INITIALIZED";break;
	case CKR_PIN_INCORRECT:
			desc =  "CKR_PIN_INCORRECT";break;
	case CKR_PIN_INVALID:
			desc =  "CKR_PIN_INVALID";break;
	case CKR_PIN_LEN_RANGE:
			desc =  "CKR_PIN_LEN_RANGE";break;
	case CKR_PIN_EXPIRED:
			desc =  "CKR_PIN_EXPIRED";break;
	case CKR_PIN_LOCKED:
			desc =  "CKR_PIN_LOCKED";break;
	case CKR_SESSION_CLOSED:
			desc =  "CKR_SESSION_CLOSED";break;
	case CKR_SESSION_COUNT:
			desc =  "CKR_SESSION_COUNT";break;
	case CKR_SESSION_HANDLE_INVALID:
			desc =  "CKR_SESSION_HANDLE_INVALID";break;
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
			desc =  "CKR_SESSION_PARALLEL_NOT_SUPPORTED";break;
	case CKR_SESSION_READ_ONLY:
			desc =  "CKR_SESSION_READ_ONLY";break;
	case CKR_SESSION_EXISTS:
			desc =  "CKR_SESSION_EXISTS";break;
	case CKR_SESSION_READ_ONLY_EXISTS:
			desc =  "CKR_SESSION_READ_ONLY_EXISTS";break;
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
			desc =  "CKR_SESSION_READ_WRITE_SO_EXISTS";break;
	case CKR_SIGNATURE_INVALID:
			desc =  "CKR_SIGNATURE_INVALID";break;
	case CKR_SIGNATURE_LEN_RANGE:
			desc =  "CKR_SIGNATURE_LEN_RANGE";break;
	case CKR_TEMPLATE_INCOMPLETE:
			desc =  "CKR_TEMPLATE_INCOMPLETE";break;
	case CKR_TEMPLATE_INCONSISTENT:
			desc =  "CKR_TEMPLATE_INCONSISTENT";break;
	case CKR_TOKEN_NOT_PRESENT:
			desc =  "CKR_TOKEN_NOT_PRESENT";break;
	case CKR_TOKEN_NOT_RECOGNIZED:
			desc =  "CKR_TOKEN_NOT_RECOGNIZED";break;
	case CKR_TOKEN_WRITE_PROTECTED:
			desc =  "CKR_TOKEN_WRITE_PROTECTED";break;
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
			desc =  "CKR_UNWRAPPING_KEY_HANDLE_INVALID";break;
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:
			desc =  "CKR_UNWRAPPING_KEY_SIZE_RANGE";break;
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
			desc =  "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";break;
	case CKR_USER_ALREADY_LOGGED_IN:
			desc =  "CKR_USER_ALREADY_LOGGED_IN";break;
	case CKR_USER_NOT_LOGGED_IN:
			desc =  "CKR_USER_NOT_LOGGED_IN";break;
	case CKR_USER_PIN_NOT_INITIALIZED:
			desc =  "CKR_USER_PIN_NOT_INITIALIZED";break;
	case CKR_USER_TYPE_INVALID:
			desc =  "CKR_USER_TYPE_INVALID";break;
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
			desc =  "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";break;
	case CKR_USER_TOO_MANY_TYPES:
			desc =  "CKR_USER_TOO_MANY_TYPES";break;
	case CKR_WRAPPED_KEY_INVALID:
			desc =  "CKR_WRAPPED_KEY_INVALID";break;
	case CKR_WRAPPED_KEY_LEN_RANGE:
			desc =  "CKR_WRAPPED_KEY_LEN_RANGE";break;
	case CKR_WRAPPING_KEY_HANDLE_INVALID:
			desc =  "CKR_WRAPPING_KEY_HANDLE_INVALID";break;
	case CKR_WRAPPING_KEY_SIZE_RANGE:
			desc =  "CKR_WRAPPING_KEY_SIZE_RANGE";break;
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
			desc =  "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";break;
	case CKR_RANDOM_SEED_NOT_SUPPORTED:
			desc =  "CKR_RANDOM_SEED_NOT_SUPPORTED";break;
	case CKR_RANDOM_NO_RNG:
			desc =  "CKR_RANDOM_NO_RNG";break;
	case CKR_DOMAIN_PARAMS_INVALID:
			desc =  "CKR_DOMAIN_PARAMS_INVALID";break;
	case CKR_BUFFER_TOO_SMALL:
			desc =  "CKR_BUFFER_TOO_SMALL";break;
	case CKR_SAVED_STATE_INVALID:
			desc =  "CKR_SAVED_STATE_INVALID";break;
	case CKR_INFORMATION_SENSITIVE:
			desc =  "CKR_INFORMATION_SENSITIVE";break;
	case CKR_STATE_UNSAVEABLE:
			desc =  "CKR_STATE_UNSAVEABLE";break;
	case CKR_CRYPTOKI_NOT_INITIALIZED:
			desc =  "CKR_CRYPTOKI_NOT_INITIALIZED";break;
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			desc =  "CKR_CRYPTOKI_ALREADY_INITIALIZED";break;
	case CKR_MUTEX_BAD:
			desc =  "CKR_MUTEX_BAD";break;
	case CKR_MUTEX_NOT_LOCKED:
			desc =  "CKR_MUTEX_NOT_LOCKED";break;
	case CKR_VENDOR_DEFINED:
			desc =  "CKR_VENDOR_DEFINED";break;
	default:
		desc =  "Unknown PKCS11 error: " + std::to_string(code);break;
	}
	return desc;
}


