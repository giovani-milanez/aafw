#ifndef PKCS11_LINUX_H_
#define PKCS11_LINUX_H_

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
     returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
     returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
     returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
     returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "aafw/pkcs11/pkcs11.h"

#endif /* PKCS11_LINUX_H_ */
