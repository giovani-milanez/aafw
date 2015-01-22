/*
 * FileSystemKeyLoader.cpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/FileSystemKeyLoader.hpp"

#include "Poco/File.h"

using namespace cryptobase;

namespace aafw {

FileSystemKeyLoader::FileSystemKeyLoader(cryptobase::DigestAlg signAlg, const std::string& certLocation, const std::string& privKeyLocation, const std::string& privKeyPass) :
		signAlg_(signAlg),
		privKey_(decodePriv(privKeyLocation, privKeyPass)),
		cert_(decodeCert(certLocation)),
		certLocation_(certLocation),
		privKeyLocation_(privKeyLocation)
{
}

FileSystemKeyLoader::~FileSystemKeyLoader()
{
}

void FileSystemKeyLoader::setCertificate(const std::string& certLocation)
{
	cert_ = decodeCert(certLocation);
	certLocation_ = certLocation;
}

void FileSystemKeyLoader::setPrivateKey(const std::string& privKeyLocation, const std::string& privKeyPass)
{
	privKey_ = decodePriv(privKeyLocation, privKeyPass);
	privKeyLocation_ = privKeyLocation;
}

cryptobase::Certificate FileSystemKeyLoader::decodeCert(const std::string& certLocation)
{
	Poco::File certFile(certLocation);
	if(!certFile.exists() || !certFile.isFile())
		throw FileNotFoundException("File "+certLocation+" not found.");

	ByteArray certBa = createFromFile(certLocation);
	std::string certStr = std::string((const char *)certBa.begin(), certBa.size());

	// tries to instantiate a DER certificate
	try{
		return Certificate(certBa);
	}catch(...){}

	// tries to instantiate a PEM certificate
	try{
		return Certificate(certStr);
	}catch(...){}

	// all failed!
	throw EncodeException("The file "+certLocation+" is not a valid certificate PEM or DER encode format");

}

cryptobase::PrivateKey FileSystemKeyLoader::decodePriv(const std::string& privKeyLocation, const std::string& privKeyPass)
{
	Poco::File privFile(privKeyLocation);
	if(!privFile.exists() || !privFile.isFile())
		throw FileNotFoundException("File "+privKeyLocation+" not found.");

	ByteArray privBa = createFromFile(privKeyLocation);
	std::string privStr = std::string((const char *)privBa.begin(), privBa.size());

	try{
		return PrivateKey(privBa);
	}catch(...){}
	try{
		return PrivateKey(privStr, privKeyPass);
	}catch(...){}
	throw EncodeException("The file "+privKeyLocation+" is not a valid private key PEM or DER encode format OR the password is incorrect");


}

} /* namespace aafw */
