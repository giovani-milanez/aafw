/*
 * AttributeAuthority.hpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTEAUTHORITY_HPP_
#define ATTRIBUTEAUTHORITY_HPP_

#include "aafw/Defs.h"
#include "aafw/SystemFactory.hpp"
#include "aafw/AttributeValidator.hpp"
#include "aafw/CRLPublisher.hpp"
#include "aafw/ACTemplate.hpp"

#include "cryptobase/AttributeCertificateReq.hpp"
#include "cryptobase/AttributeCertificateResp.hpp"

#include "Poco/Util/ServerApplication.h"
#include "Poco/Crypto/OpenSSLInitializer.h"


namespace aafw {

CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, AlreadyRegisteredException, cryptobase::Exception)
CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, NoSuchException, cryptobase::Exception)

class AAFW_API AttributeAuthority : public Poco::Util::ServerApplication
{
public:
	AttributeAuthority();
	virtual ~AttributeAuthority();

	virtual std::unique_ptr<SystemFactory> getSystemFactory() = 0;

	/**
	  * You should register your attributes validador, templates or CRL publisher.
	  * eg, 
	  * registerValidator("1.1.1.1", std::unique_ptr<AttributeValidador>(new AllowValidator));
	  * unregisterCRLPublisher("1.1.1.1", std::unique_ptr<AttributeValidador>(new FileSystemCRLPublisher(...));
	  */
	virtual void setup() = 0;

	cryptobase::AttributeCertificateResp handleRequest(const cryptobase::AttributeCertificateReq& req);

	/**
	 * Register an Attribute Validator that will be called to
	 * validate AttributeCertificateReq attributes, if present.
	 * @throw NullPointerException in case of validator being null
	 * @throw AlreadyRegisteredException if the validator for OID
	 * is already registered.
	 */
	void registerValidator(const std::string& oid, AttributeValidator *validator);

	/**
	 * Unregister the Attribute Validator for the specified OID.
	 * @throw NoSuchException if an AttributeValidator with the OID
	 * specified is not found
	 */
	void unregisterValidator(const std::string& oid);

	/**
	 *  Register a CRL publisher for using when requested the attribute revocation.
	 */
	void registerCRLPublisher(const std::string& oid, CRLPublisher *publisher);

	/**
	  * Unregister the CRL publisher for the attribute oid specified
	  */
	void unregisterCRLPublisher(const std::string& oid);
	
	void registerAttributeCertificateTemplate(int templateId, ACTemplate *acTemplate);
	void unregisterAttributeCertificateTemplate(int templateId);

	/**
	 * Tells that the AttributeAuthority must deny the request
	 * if an unknown attribute is requested. The known attributes are the
	 * ones registered by registerValidator.
	 */
	void denyUnknownAttributes();

	/**
	 * Tells that the AttributeAuthority must deny the request
	 * if no attributes requested.
	 */
	void denyEmptyAttributes();

	/**
	 * Changes the message when issuing a rejection response
	 * because of unknown attribute
	 */
	void unknownAttributeMessage(const std::string& msg);

	/**
	 * Changes the message when issuing a rejection response
	 * because of empty attribute
	 */
	void emptyAttributeMessage(const std::string& msg);

	/**
	 * Sets the CRL validity to be used
	 * when publishing CRL
	 */
	void setCrlMinutesValidity(long minutesValidity);

	/**
	 * When an exception is captured from TransportServer (eg. TCPTransportServer)
	 * this method will be called.
	 * Default behavior is to print error message to stdout.
	 */
	virtual void handleTransportError(const std::exception& ex);

	virtual void initialize(Poco::Util::Application& self);
	virtual void uninitialize();
	void defineOptions(Poco::Util::OptionSet& options);
	int main(const std::vector<std::string>& args);
private:
	friend class CRLHouseKeep;
	Poco::Crypto::OpenSSLInitializer oi_;

	std::unique_ptr<SystemFactory> factory_;
	std::unique_ptr<ACStore> acStore_;
	std::unique_ptr<KeyLoader> keyLoader_;
	std::unique_ptr<ACSerialLoader> serialLoader_;
	std::unique_ptr<TransportServer> transportServer_;

	std::map<std::string, std::unique_ptr<AttributeValidator>> validators_;
	std::map<std::string, std::unique_ptr<CRLPublisher>> publishers_;
	std::map<int, std::unique_ptr<ACTemplate>> templates_;
	
	bool denyUnknownAttributes_, denyEmptyAttributes_;
	std::string unkownAttributeMessage_, emptyAttributeMessage_;	

	void revoke(std::unique_ptr<CRLPublisher>& crlPublisher, const std::string& acSerial);
	cryptobase::AttributeCertificate issueAttributeCertificate(const cryptobase::AttributeCertificateIssueInfo& issueInfo);
	std::vector<cryptobase::AttributeCertificate> searchAttributeCertificate(const cryptobase::AttributeCertificateSearchInfo& searchInfo);
};

inline void AttributeAuthority::denyUnknownAttributes()
{
	denyUnknownAttributes_ = true;
}

inline void AttributeAuthority::denyEmptyAttributes()
{
	denyEmptyAttributes_ = true;
}

inline void AttributeAuthority::unknownAttributeMessage(const std::string& msg)
{
	unkownAttributeMessage_ = msg;
}

inline void AttributeAuthority::emptyAttributeMessage(const std::string& msg)
{
	emptyAttributeMessage_ = msg;
}



} /* namespace aafw */
#endif /* ATTRIBUTEAUTHORITY_HPP_ */
