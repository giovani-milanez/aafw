/*
 * RandomACSerialLoader.cpp
 *
 *  Created on: 13/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/RandomACSerialLoader.hpp"

#include <time.h>

namespace aafw {

RandomACSerialLoader::RandomACSerialLoader() :
		engine_(static_cast<unsigned long>(time(nullptr))),
		dist_(1, std::numeric_limits<std::uint32_t>::max())
{
}

RandomACSerialLoader::~RandomACSerialLoader()
{
}

uint64_t RandomACSerialLoader::nextSerial()
{
	return dist_(engine_);
}

} /* namespace aafw */
