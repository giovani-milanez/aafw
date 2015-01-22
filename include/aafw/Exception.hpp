/*
 * Exception.hpp
 *
 *  Created on: 24/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef AAFW_EXCEPTION_HPP_
#define AAFW_EXCEPTION_HPP_

#include "aafw/Defs.h"
#include "cryptobase/Exception.hpp"

namespace aafw {

CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, RejectRequestException, cryptobase::Exception)
CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, NoRequestHandlerMatchException, cryptobase::Exception)

/**
 * Represents a PKCS#11 Error Code.
 * You may obtain the CK_RV from code() method.
 * The message() method will stringfy the error code.
 */
CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, Pkcs11Exception, cryptobase::Exception)

}

#endif /* EXCEPTION_HPP_ */
