/*
 * RandomACSerialLoader.hpp
 *
 *  Created on: 13/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef RANDOMACSERIALLOADER_HPP_
#define RANDOMACSERIALLOADER_HPP_

#include "aafw/Defs.h"
#include "aafw/ACSerialLoader.hpp"

#include <random>

namespace aafw {

/**
 * Implements a pseudorandom serial number generator.
 */
class AAFW_API RandomACSerialLoader : public ACSerialLoader
{
public:
	RandomACSerialLoader();
	virtual ~RandomACSerialLoader();

	/**
	 * Generates a pseudorandom (Mersenne Twister) serial number.
	 * @return pseudorandom number betwen 1 and std::numeric_limits<std::uint32_t>::max(), uniform distribution.
	 * @throw May throw  std::exception
	 */
	uint64_t nextSerial();
private:
	std::mt19937 engine_;
	std::uniform_int_distribution<std::uint32_t> dist_;
};

} /* namespace aafw */
#endif /* RANDOMACSERIALLOADER_HPP_ */
