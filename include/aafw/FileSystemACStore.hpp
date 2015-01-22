/*
 * FileSystemACStore.hpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef FILESYSTEMACSTORE_HPP_
#define FILESYSTEMACSTORE_HPP_

#include "aafw/Defs.h"
#include "aafw/ACStore.hpp"

#include "cryptobase/EncodingType.hpp"
#include "cryptobase/MessageDigest.hpp"

#include "Poco/Util/PropertyFileConfiguration.h"

#include <string>

namespace aafw {

/**
 * Implements AC filesystem storage. The file name will be based on the serial. Example: 10.ac
 * It uses index.properties to keep track of issued ACs. Its a key-value file where key is the Holder fingerprint (SHA1)
 * and value its AC serials, Example: 1D97EC5F447FB9BAB91D47B8A31FDDBE0ED5B1DD: 36,37
 */
class AAFW_API FileSystemACStore: public ACStore
{
public:
	/**
	 * Set the path where to store the ACs and the encoding type used to store the AC.
	 * May throw PathNotFoundException if path not found.
	 */
	FileSystemACStore(const std::string& path, cryptobase::EncodingType encoding = cryptobase::EncodingType::DER);
	virtual ~FileSystemACStore();

	/**
	 * Stores the AC on the given path and encoding type.
	 * File name will be based on serial. Example: 10.ac
	 */
	void saveAc(const cryptobase::AttributeCertificate& ac);

	cryptobase::EncodingType getEncoding() const;

	/**
	 * Set the encoding type (pem, der) used to store the AC
	 */
	void setEncoding(cryptobase::EncodingType encoding);

	const std::string& getPathToSave() const;

	/**
	 * Set the path where to store the ACs.
	 * Throw PathNotFoundException if path not found.
	 */
	void setPathToSave(const std::string& pathToSave);

	/**
	 * Find in index.properties the ACs issued for the specified Holder.
	 */
	std::vector<cryptobase::AttributeCertificate> retrieveAc(const cryptobase::Holder& holder);
	/**
	 * Find in index.properties the ACs containing any of the attrsOid issued for the specified Holder.
	 */
	std::vector<cryptobase::AttributeCertificate> retrieveAc(const cryptobase::Holder& holder, const std::vector<cryptobase::ObjectIdentifier>& attrsOid);

	cryptobase::AttributeCertificate retrieveAc(const std::string& acSerial);

	std::string getFileName(const std::string& serial) const;

private:
	std::string pathToSave_;
	cryptobase::EncodingType encoding_;
	cryptobase::MessageDigest md_;
	const std::string INDEX_FILE;
	Poco::AutoPtr<Poco::Util::PropertyFileConfiguration> indexer_;	
};


inline cryptobase::EncodingType FileSystemACStore::getEncoding() const
{
	return encoding_;
}

inline void FileSystemACStore::setEncoding(cryptobase::EncodingType encoding)
{
	encoding_ = encoding;
}

inline const std::string& FileSystemACStore::getPathToSave() const
{
	return pathToSave_;
}

} /* namespace aafw */
#endif /* FILESYSTEMACSTORE_HPP_ */
