/*
 * ACSerialLoader.hpp
 *
 *  Created on: 13/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ACSERIALLOADER_HPP_
#define ACSERIALLOADER_HPP_

#include <cstdint>

namespace aafw {

/**
 * An interface responsible for generating unique serials for each call of nextSerial().
 * The serial will be used to compose the AC.
 */
class ACSerialLoader
{
public:
	/**
	 * Generate an unique serial number.
	 */
	virtual uint64_t nextSerial() = 0;
	virtual ~ACSerialLoader(){};
};

}

#endif /* ACSERIALLOADER_HPP_ */
