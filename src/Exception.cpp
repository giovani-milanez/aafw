/*
 * Exception.cpp
 *
 *  Created on: 24/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */


#include "aafw/Exception.hpp"

#include <typeinfo>

namespace aafw {

CRYPTOBASE_IMPLEMENT_EXCEPTION(RejectRequestException, cryptobase::Exception, "The Request has been rejected")
CRYPTOBASE_IMPLEMENT_EXCEPTION(NoRequestHandlerMatchException, cryptobase::Exception, "No Request Handler Match")
CRYPTOBASE_IMPLEMENT_EXCEPTION(Pkcs11Exception, cryptobase::Exception, "PKCS#11 Exception")

}
