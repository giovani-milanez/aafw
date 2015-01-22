# aafw
Attribute Authority Framework

This project is the result of my final paper and its aimed to be used by attribute authrorities that needs 
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

## Examples
The most basic AA application uses the already provided framework interfaces implementation.
In order to use the framwork one must inherit <i>AttributeAuthority</i> class and implement its abstracts methods.

The following application will respond to attribute certificate requests, for the attribute of OID 2.30.50.1.1.1.
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

class MinhaEEA : public AttributeAuthority
{
public:
	std::unique_ptr<SystemFactory> getSystemFactory()
	{
		return std::unique_ptr<SystemFactory>(new DefaultFactory);
	}
	void setup()
	{
		registerValidator("2.30.50.1.1.1", new AllowValidator);
		registerCRLPublisher("2.30.50.1.1.1", new FileSystemCRLPublisher(60, "http://minhaEEA.com/eea.crl", "C:\\eea.crl"));
		denyUnknownAttributes();
	}
};

int main(int argc, char ** argv)
{
	try
	{
		MinhaEEA eea;
		return eea.run(argc, argv);
	}
	catch(...)
	{
		std::cerr << "something bad happened" << std::endl;
	}
}
```
