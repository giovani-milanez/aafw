/*
 * CRLHouseKeep.hpp
 *
 *  Created on: 01/06/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef CRLHOUSEKEEP_HPP_
#define CRLHOUSEKEEP_HPP_

#include "aafw/Defs.h"
#include "Poco/Util/Subsystem.h"
#include "Poco/Timer.h"

namespace aafw {

/**
 * Keep checking for CRL expiration time. If it is close to expire a new one will be issued.
 */
class AAFW_API CRLHouseKeep : public Poco::Util::Subsystem
{
public:
	CRLHouseKeep();
	virtual ~CRLHouseKeep();

	const char* name() const;
	void initialize(Poco::Util::Application& app);
	void uninitialize();

	/**
	  * It will issue a new CRL if it is publicationThreshold close to expire.
	  * publicationThreshold is expressed in seconds
	  */
	long publicationThreshold;
private:
	/**
	 * Checks if CRL nextUpdate is publicationThreshold seconds close to expire.
	 * If true it will republish a new CRL.
	 */
	void tryRepublish(Poco::Timer& timer);

	Poco::Timer timer_;
	Poco::TimerCallback<CRLHouseKeep> cb_;

	static const long DEFAULT_PUBLICATION_THRESHOLD_SECONDS = 5 * 60; // 5 minutes
};


} /* namespace aafw */

#endif /* CRLHOUSEKEEP_HPP_ */
