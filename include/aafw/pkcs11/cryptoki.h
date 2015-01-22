#ifndef CRYPTOKI_H_
#define CRYPTOKI_H_

#include "Poco/Foundation.h"

#if defined(POCO_OS_FAMILY_UNIX)
#include "aafw/pkcs11/pkcs11_linux.h"
#elif defined(POCO_OS_FAMILY_WINDOWS)
#include "aafw/pkcs11/pkcs11_windows.h"
#endif

struct KeyCtx {
	CK_OBJECT_HANDLE keyHandle_;
	CK_SESSION_HANDLE sessionHandle_;
	CK_FUNCTION_LIST_PTR funcs_;
};


extern int rsaIdx;

typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;

int freeRsaExData(RSA *r);
int rsaSign(int type, const unsigned char *m, unsigned int m_len,
			unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
RSA_METHOD *getRsaMethod();

std::string pkcs11Error2Message(CK_RV code);

#endif /* CRYPTOKI_H_ */
