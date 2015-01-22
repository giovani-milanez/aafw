#ifndef NOCRLPUBLISHER_HPP_
#define NOCRLPUBLISHER_HPP_

#include "aafw/Defs.h"
#include "aafw/CRLPublisher.hpp"

namespace aafw {

class AAFW_API NoCRLPublisher : public CRLPublisher
{
public:
	void publish(const cryptobase::CertificateRevocationList& crl);
	std::unique_ptr<cryptobase::CertificateRevocationList> get() const;
	std::string getDistPointUrl() const;
};

} /* namespace aafw */
#endif /* NOCRLPUBLISHER_HPP_ */

