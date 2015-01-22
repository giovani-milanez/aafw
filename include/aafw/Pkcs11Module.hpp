/*
 * Pkcs11Module.hpp
 *
 *  Created on: 14/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef PKCS11MODULE_HPP_
#define PKCS11MODULE_HPP_

#include "aafw/Pkcs11Session.hpp"

#include "Poco/SharedLibrary.h"

namespace aafw {

/**
 * Represents a PKCS#11 module.
 */
class AAFW_API Pkcs11Module {
public:
	/**
	 * Loads the module and initialize it (C_Initialize) using the library indicated by moduleLocation
	 */
	Pkcs11Module(const std::string& moduleLocation);
	virtual ~Pkcs11Module();

	/**
	 * Opens a session on the specified slot and login if pin is supplied.
	 * @param slotId The slot to open a session
	 * @param pin The pin to login
	 * @throw Pkcs11Exception if CK_RV is different than CKR_OK
	 */
	Pkcs11Session openSession(CK_SLOT_ID slotId, const std::string& pin = "");
	/**
	 * Locates the slot id based on slotLabel and login if pin is supplied.
	 * @param slotLabel The slot label
	 * @param pin The pin to login
	 * @throw Pkcs11Exception if CK_RV is different than CKR_OK
	 * @throw NotFoundException if the slotLabel doesnt match any PKCS#11 Slot
	 */
	Pkcs11Session openSession(const std::string& slotLabel, const std::string& pin = "");

	/**
	 * Finds a slot ID based on slot label
	 * @param label The slot label
	 * @return The slot id found
	 * @throw Pkcs11Exception if CK_RV is different than CKR_OK
	 * @throw NotFoundException if the slotLabel doesnt match any PKCS#11 Slot
	 */
	CK_SLOT_ID findTokenFromName(const std::string& label);
private:
	Pkcs11Module(const Pkcs11Module&);
	Pkcs11Module& operator = (const Pkcs11Module&);

	Poco::SharedLibrary lib_;
	CK_FUNCTION_LIST_PTR funcs_;
	bool mustFinalize_;
};

} /* namespace aafw */
#endif /* PKCS11MODULE_HPP_ */
