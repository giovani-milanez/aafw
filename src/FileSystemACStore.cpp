/*
 * FileSystemACStore.cpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/FileSystemACStore.hpp"

#include "cryptobase/AttributeCertificate.hpp"

#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/StringTokenizer.h"

#include <fstream>
#include <iostream>

namespace aafw {

FileSystemACStore::FileSystemACStore(const std::string& path, cryptobase::EncodingType encoding) :
		encoding_(encoding),
		md_(cryptobase::DigestAlg::SHA1),
		INDEX_FILE("index.properties")
{
	setPathToSave(path);
}

FileSystemACStore::~FileSystemACStore()
{
}

void FileSystemACStore::saveAc(const cryptobase::AttributeCertificate& ac)
{
	cryptobase::AttributeCertificateInfo info = ac.getInfo();
	std::string serial = info.getSerialString();
	std::string filePath = getFileName(serial);
	std::ofstream os(filePath.c_str());

	if(encoding_ == cryptobase::EncodingType::DER)
		os << ac.getDerEncoded();
	else
		os << ac.getPemEncoded();


	cryptobase::ByteArray digest = md_.doFinal(info.getHolder().getDerEncoded());
	std::string digestHex = cryptobase::hex(digest);
	try
	{
		std::string serials = indexer_->getString(digestHex);
		indexer_->setString(digestHex, serials+","+serial);
	}
	catch(const Poco::NotFoundException& ex)
	{
		indexer_->setString(digestHex, serial);
	}
	indexer_->save(pathToSave_ + INDEX_FILE);
}

void FileSystemACStore::setPathToSave(const std::string& pathToSave)
{
	std::string path = pathToSave;

	// check if last character is the separator. If not, add it.
	if(path[path.size() -1] != Poco::Path::separator())
		path += Poco::Path::separator();

	Poco::File f(path);
	if(!f.exists() || !f.isDirectory())
		throw cryptobase::PathNotFoundException("Path "+pathToSave+" does not exist");

	pathToSave_ = path;
	Poco::File fileIndex(pathToSave_ + INDEX_FILE);
	if(!fileIndex.exists())
		fileIndex.createFile();

	indexer_ = new Poco::Util::PropertyFileConfiguration(pathToSave_ + INDEX_FILE);
}

std::vector<cryptobase::AttributeCertificate> FileSystemACStore::retrieveAc(const cryptobase::Holder& holder)
{
	std::vector<cryptobase::AttributeCertificate> acs;

	cryptobase::ByteArray digest = md_.doFinal(holder.getDerEncoded());
	std::string digestHex = cryptobase::hex(digest);
	try
	{
		std::string serials = indexer_->getString(digestHex);
		Poco::StringTokenizer tokens(serials, ",");
		for(auto serial : tokens)
		{
			cryptobase::ByteArray ba = cryptobase::createFromFile(getFileName(serial));
			try{
				acs.push_back(cryptobase::AttributeCertificate(ba));
			}catch(const cryptobase::DerDecodeException& ex){
				try{
					acs.push_back(cryptobase::AttributeCertificate(std::string((const char *)ba.begin(), ba.size())));
				}catch(const cryptobase::PemDecodeException& ex){
					// invalid ac!
				}
			}
		}
	}
	catch(const Poco::NotFoundException& ex)
	{
	}

	return acs;
}

std::vector<cryptobase::AttributeCertificate> FileSystemACStore::retrieveAc(const cryptobase::Holder& holder, const std::vector<cryptobase::ObjectIdentifier>& attrsOid)
{
	std::vector<cryptobase::AttributeCertificate> acs;
	for(auto ac : retrieveAc(holder))
	{
		for(auto attr : ac.getInfo().getAttributes())
		{
			auto it = std::find_if(attrsOid.begin(), attrsOid.end(),
					[&](const cryptobase::ObjectIdentifier& obj)
					{
						return obj == attr.getOid();
					});
			if(it != attrsOid.end())
				acs.push_back(ac);
		}
	}
	return acs;
}

cryptobase::AttributeCertificate FileSystemACStore::retrieveAc(const std::string& acSerial)
{
	std::string file = getFileName(acSerial);
	Poco::File f(file);
	if(!f.exists())
		throw cryptobase::NotFoundException("The attribute certificate requested does not exist");

	cryptobase::ByteArray ba = cryptobase::createFromFile(file);
	try{
		return cryptobase::AttributeCertificate(ba);
	}catch(const cryptobase::DerDecodeException& ex){
		try{
			return cryptobase::AttributeCertificate(std::string((const char *)ba.begin(), ba.size()));
		}catch(const cryptobase::PemDecodeException& ex){
			// invalid ac!
			throw cryptobase::NotFoundException("The attribute certificate requested is corrupted");
		}
	}
}

std::string FileSystemACStore::getFileName(const std::string& serial) const
{
	Poco::Path p(pathToSave_);
	return p.toString() + serial + ".ac";
}

} /* namespace aafw */
