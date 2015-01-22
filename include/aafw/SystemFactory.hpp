/*
 * SystemFactory.hpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef SYSTEMFACTORY_HPP_
#define SYSTEMFACTORY_HPP_

#include <memory>

namespace aafw {

class ACStore;
class KeyLoader;
class ACSerialLoader;
class TransportServer;

class SystemFactory
{
public:
	virtual ~SystemFactory(){}

	virtual std::unique_ptr<ACStore> getACStore() const = 0;
	virtual std::unique_ptr<KeyLoader> getKeyLoader() const = 0;
	virtual std::unique_ptr<ACSerialLoader> getACSerialLoader() const = 0;
	virtual std::unique_ptr<TransportServer> getTransportServer() const = 0;
};

}


#endif /* SYSTEMFACTORY_HPP_ */
