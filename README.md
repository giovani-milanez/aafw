# Attribute Authority Framework

This project is the result of my final paper and its aimed to be used by attribute authorities that needs 
to manage the life cycle of their attribute certificates.

[Final Paper (Portuguese)] (https://projetos.inf.ufsc.br/arquivos_projetos/projeto_1540/TCC_Framework_Certificado_Atributo_Giovani_Milanez_v2.pdf)

<i>
<p style='text-align: center;'>Abstract: The X.509 attribute certificate is a digitally signed document that establish
assignments to a entity. In July 2012, the technology was standardized
for use in Brazil by ICP-Brasil. Because it is a relatively new technology in that
country, the development support for systems that uses attribute certificate still
lack of studies and references. The author proposes a request-response protocol
for attribute certificate issuance, search and revocation. Such protocol was
implemented in a object oriented framework that allows the construction of applications
that need to manage the life cycle of that certificates. The framework
was used to build a prototype application for cinema ticket management.
</p>
</i>

## Use Case Diagram

The frameworks goal is to respond to attribute certificate issuance, search and revocation requests, as shown in the use case diagram.

![Use Case](use_case_aafw.png?raw=true)

The life cycle of a attribute certificate starts with a issuance request from a thirty party. The request is processed and the holder's situation will be verified in order to aprove the issuance. After that the AC will be issued. The publication using either a <i>push</i> or <i>pull</i> method is needed so that it can be consumed. Once publish the holder can benefit from it until it expires. 
While the AC is in its validity it can be revoked, causing the holder's privillege to be cancelled.
Also, the AC verifier may query the Attribute Authority to check if the entity trying to access the protected resource has the rights to do so (has an AC expliciting it).
The life cycle ends when the AC validity expires.

## Class Diagram

The simplified diagram class show a scenario where the framework user create a subclass of <i>AttributeAuthority</i> called <i>MinhaEEA</i> (MyAA in english), the green rectangle.
The framework interfaces are represented by the blue rectangles.
The orange rectangles represent some of the interfaces implementation provided by the framework.
Implementing the framework interfaces is the way to change its behaviour.

![Classes](classes_aafw.png?raw=true)

The behaviours that can be changed are:
- How to load the digital certificate, private key and algorithm to perform the AC signature
- How to store and search in a repository the issued attribute certificates
- How to obtain the next serial number of the AC to be issued
- How to receive and send <i>AttributeCertificateReq</i> and <i>AttributeCertificateResp</i> messages
- How and where to publish revoked AC
- How to validate if the attributes present in a issuance request are acceptable for the requested holder
- How to handle the <i>templateId</i> field present in a request

## Examples
The most basic AA application uses the already provided framework interfaces implementation.
In order to use the framework one must inherit <i>AttributeAuthority</i> class and implement its abstracts methods.

The following application will respond through RPC or TCP protocol, as defined in the paper, to attribute certificate requests, for the attribute of OID 2.30.50.1.1.1.

The <i>AllowValidadtor</i> is linked to the attribute, so whenever a request for that attribute is received the
validator will trigger. The validator must tell if the holder present in the request has the privileges to obtain such attribute. 
The <i>AllowValidator</i> is implemented so that no validation is done, always granting the holder the attribute requested.

```c++
#include "aafw/AttributeAuthority.hpp"
#include "aafw/DefaultFactory.hpp"
#include "aafw/AllowValidator.hpp"
#include "aafw/FileSystemCRLPublisher.hpp"

#include <iostream>

using namespace aafw;
using namespace cryptobase;

class MyAA : public AttributeAuthority
{
public:
	std::unique_ptr<SystemFactory> getSystemFactory()
	{
		return std::unique_ptr<SystemFactory>(new DefaultFactory);
	}
	void setup()
	{
		registerValidator("2.30.50.1.1.1", new AllowValidator);
		registerCRLPublisher("2.30.50.1.1.1", new FileSystemCRLPublisher(60, "http://myaa.com/aa.crl", "C:\\aa.crl"));
		denyUnknownAttributes();
	}
};

int main(int argc, char ** argv)
{
	try
	{
		MyAA aa;
		return aa.run(argc, argv);
	}
	catch(...)
	{
		std::cerr << "something bad happened" << std::endl;
	}
}
```

## Dependencies

[POCO C++ Libraries] (http://pocoproject.org/)

[Apache Thrift] (http://thrift.apache.org/)

[cryptobase] (https://github.com/giovani-milanez/cryptobase)
