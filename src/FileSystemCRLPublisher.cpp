/*
 * FileSystemCRLPublisher.cpp
 *
 *  Criado em: 18/03/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "aafw/FileSystemCRLPublisher.hpp"
#include "aafw/FileSystemACSerialLoader.hpp"

#include "cryptobase/ByteArray.hpp"

#include "Poco/File.h"

namespace aafw {

FileSystemCRLPublisher::FileSystemCRLPublisher(long crlValidity, const std::string& distPoint, const std::string& filePath, cryptobase::EncodingType encoding) :
		pathToSave_(filePath),
		distPoint_(distPoint),
		encoding_(encoding),
		crlValidity_(crlValidity)
{
}

FileSystemCRLPublisher::~FileSystemCRLPublisher()
{
}

void FileSystemCRLPublisher::publish(const cryptobase::CertificateRevocationList& crl)
{
	std::ofstream os(pathToSave_.c_str());

	if(encoding_ == cryptobase::EncodingType::DER)
		os << crl.getDerEncoded();
	else
		os << crl.getPemEncoded();
}

std::unique_ptr<cryptobase::CertificateRevocationList> FileSystemCRLPublisher::get() const
{
	std::unique_ptr<cryptobase::CertificateRevocationList> crl(nullptr);
	Poco::File f(pathToSave_);
	if(!f.exists())
		return crl; // CRL not yet published

	cryptobase::ByteArray fileBa = cryptobase::createFromFile(pathToSave_);
	if(encoding_ == cryptobase::EncodingType::DER)
		crl.reset(new cryptobase::CertificateRevocationList(fileBa));
	else
		crl.reset(new cryptobase::CertificateRevocationList(std::string((const char *)fileBa.begin(), fileBa.size())));

	return crl;

}

std::string FileSystemCRLPublisher::getDistPointUrl() const
{
	return distPoint_;
}

long FileSystemCRLPublisher::getMinutesValidity() const
{
	return crlValidity_;
}

std::unique_ptr<ACSerialLoader> FileSystemCRLPublisher::getSerialLoader() const
{
	return std::unique_ptr<ACSerialLoader>(new FileSystemACSerialLoader(pathToSave_+".serial"));

}


} /* namespace aafw */
