/*
 * FileSystemACSerialLoader.hpp
 *
 *  Created on: 13/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef FILESYSTEMACSERIALLOADER_HPP_
#define FILESYSTEMACSERIALLOADER_HPP_

#include "aafw/Defs.h"
#include "aafw/ACSerialLoader.hpp"

#include <string>

namespace aafw {

/**
 * Implements filesystem serial loader.
 */
class AAFW_API FileSystemACSerialLoader: public ACSerialLoader
{
public:
	/**
	 * The file holding the last serial number.
	 * If the file does not exists it will be created and the call of nextSerial() will return 1.
	 */
	FileSystemACSerialLoader(const std::string& fileLocation);
	virtual ~FileSystemACSerialLoader();

	/**
	 * Reads the last serial number from the file, increments it by 1 and update the file.
	 */
	uint64_t nextSerial();
private:
	std::string fileLocation_;
};

} /* namespace aafw */
#endif /* FILESYSTEMACSERIALLOADER_HPP_ */
