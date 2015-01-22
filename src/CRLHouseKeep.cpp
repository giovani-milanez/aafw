/*
 * CRLHouseKeep.cpp
 *
 *  Created on: 01/06/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/CRLHouseKeep.hpp"
#include "aafw/AttributeAuthority.hpp"

#include "Poco/Util/Application.h"
#include "Poco/DateTime.h"

namespace aafw {

CRLHouseKeep::CRLHouseKeep() : 
	publicationThreshold(DEFAULT_PUBLICATION_THRESHOLD_SECONDS),
	cb_(*this, &CRLHouseKeep::tryRepublish)
{
}

CRLHouseKeep::~CRLHouseKeep()
{
}

const char* CRLHouseKeep::name() const
{
	return "CRLHouseKeep";
}

void CRLHouseKeep::initialize(Poco::Util::Application& app)
{	
	timer_.setStartInterval(0);
	timer_.setPeriodicInterval(1000 * 60); // 1 minute interval
	timer_.start(cb_);
}

void CRLHouseKeep::uninitialize()
{
	timer_.stop();
}

void CRLHouseKeep::tryRepublish(Poco::Timer& timer)
{
	AttributeAuthority& aa = dynamic_cast<AttributeAuthority&>(Poco::Util::Application::instance());
	for(auto& it : aa.publishers_)
	{
		auto crl = it.second->get();
		if(crl != nullptr)
		{
			Poco::DateTime now;
			time_t nextEpoch = crl->getNextUpdate();
			time_t nowEpoch = now.timestamp().epochTime();		
			time_t diff = nextEpoch - nowEpoch;
			if(diff <= publicationThreshold)
			{
				aa.revoke(it.second, std::string("")); // actually not revoking, just republishing with new expiration date
			}
		}
	}
}

} /* namespace aafw */
