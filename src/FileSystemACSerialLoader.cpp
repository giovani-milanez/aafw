/*
 * FileSystemACSerialLoader.cpp
 *
 *  Created on: 13/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/FileSystemACSerialLoader.hpp"

#include "cryptobase/Exception.hpp"

#include "Poco/File.h"

#include <fstream>

namespace aafw {

FileSystemACSerialLoader::FileSystemACSerialLoader(const std::string& fileLocation) :
		fileLocation_(fileLocation)
{
	Poco::File f(fileLocation_);
	if(!f.exists())
		f.createFile();
}

FileSystemACSerialLoader::~FileSystemACSerialLoader()
{
}

uint64_t FileSystemACSerialLoader::nextSerial()
{
	std::fstream fileStream(fileLocation_, std::fstream::in | std::fstream::out);
	if(!fileStream.is_open())
		throw cryptobase::OpenFileException("File "+fileLocation_+" is closed.");

	// read
	uint64_t lastSerial = 0;
	fileStream >> lastSerial;
	fileStream.close();

	// write
	fileStream.open(fileLocation_, std::fstream::in | std::fstream::out | std::fstream::trunc);
	fileStream << ++lastSerial;

	return lastSerial; // actually the next serial because of ++lastSerial

}

} /* namespace aafw */
