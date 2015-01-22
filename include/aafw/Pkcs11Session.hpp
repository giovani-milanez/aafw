/*
 * Pkcs11Session.hpp
 *
 *  Created on: 14/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef PKCS11SESSION_HPP_
#define PKCS11SESSION_HPP_

#include "aafw/Defs.h"
#include "aafw/pkcs11/cryptoki.h"

#include "cryptobase/PrivateKey.hpp"
#include "cryptobase/Certificate.hpp"

#include <vector>

namespace aafw {

/**
 * Represents a PKCS#11 Session.
 * It will open session in constructor and close it in destructor. It will also logout in destructor if it is logged in.
 * Be carefull whith the Pkcs11Session object scope. For example, if the object get out of scope or destroyed and a key returned by extractPkcs11Key method is still alive,
 * it will become invalid, since the session was closed.
 */
class AAFW_API Pkcs11Session
{
public:
	/**
	 * Open the session (CKF_SERIAL_SESSION|CKF_RW_SESSION) and login if the pin isnt empty.
	 * @param funcs The PKCS#11 function list from the module loaded.
	 * @param slot The slot ID to open the session
	 * @param pin The pin to login the session. If the pin is empty, no login will be made.
	 * @throw NullPointerException if funcs is null
	 * @throw Pkcs11Exception if CK_RV is different than CKR_OK
	 */
	Pkcs11Session(CK_FUNCTION_LIST_PTR funcs, CK_SLOT_ID slot, const std::string& pin = "");
	virtual ~Pkcs11Session();

	/**
	 * Login on slot_ as CKU_USER.
	 * @throw Pkcs11Exception if CK_RV is different than CKR_OK and CKR_USER_ALREADY_LOGGED_IN
	 */
	void login(const std::string& pin);
	/**
	 *	Finds a object with the specified name and class.
	 *	It will return the first found.
	 *	@param objLabel The object label to search for
	 *	@param objClass The object class
	 *	@throw Pkcs11Exception if CK_RV is different than CKR_OK
	 *	@throw NotFoundException if no object is found
	 */
	CK_OBJECT_HANDLE findObject(const std::string& objLabel, CK_OBJECT_CLASS objClass);
	/**
	 * Grab the properties of keyHandle and create an cryptobase::PrivateKey.
	 * Only RSA supported for now.
	 * @param keyHandle the PKCS#11 key handle (eg. obtained by findObject)
	 * @return The private key extracted
	 * @throw Pkcs11Exception if CK_RV is different than CKR_OK
	 */
	cryptobase::PrivateKey extractPkcs11Key(CK_OBJECT_HANDLE keyHandle);
	/**
	 * Grab the properties of certHandle and create an cryptobase::Certificate.
	 * @param keyHandle the PKCS#11 ceritificate handle (eg. obtained by findObject)
	 * @return The X509 certificate extracted
	 * @throw Pkcs11Exception if CK_RV is different than CKR_OK
	 */
	cryptobase::Certificate extractCertificate(CK_OBJECT_HANDLE certHandle);
private:
	CK_FUNCTION_LIST_PTR funcs_;
	CK_SLOT_ID slot_;
	CK_SESSION_HANDLE sessionHandle_;
	std::vector<KeyCtx> ctxs_;

	bool loggedIn_;
};

} /* namespace aafw */
#endif /* PKCS11SESSION_HPP_ */
