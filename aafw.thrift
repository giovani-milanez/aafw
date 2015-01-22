/**
 * Thrift files can namespace, package, or prefix their output in various
 * target languages.
 */
namespace cpp aafw
namespace java aafw
namespace php aafw

/**
* key = OID and value = any string
* Example: <"2.5.4.3", "Giovani Milanez">
*/
typedef map<string,string> X509Name // RDNSequence

struct ACValidity {
   1: i32 notBeforeEpoch,
   2: i32 notAfterEpoch,
}

struct Extension {
   1: string oid,
   2: binary value,
}

struct Attribute {
   1: string oid,
   2: list<binary> values,
}

struct BaseCertId {
   1: X509Name issuer,
   2: string serial,
}

/**
 * Represents the AttributeCertificate Holder.
 * entityName OR baseCertId MUST be provided
 */ 
struct ACHolder {

  1: optional X509Name entityName,
  2: optional BaseCertId baseCertId,
}

struct ACInfo {
   1: i16 version,
   2: ACHolder holder,
   3: X509Name issuer,
   4: string signatureAlgorithm,
   5: i64 serial,
   6: ACValidity validity,
   7: list<Attribute> attributes,
   8: optional list<Extension> extensions,
}

struct AttributeCertificate {
   1: ACInfo info,
   2: string algor,
   3: binary signature,
   4: string pem
}

struct ACIssueInfo {
   1: ACHolder holder,
   /**
    * If templateId is provided the other fileds must not be provided.
    * If templateId is NOT provided the other fields should be provided.
    */
   2: optional i16 templateId,
   3: optional X509Name issuer,
   4: optional ACValidity validity,
   5: optional list<Attribute> attributes,
   6: optional list<Extension> extensions,
}

struct ACSearchInfo {
   1: ACHolder holder,
   2: optional set<string> attributesOid,
}

/**
 * reqInfo OR searchInfo MUST be provided
 */ 
struct ACReq {
   1: optional ACIssueInfo issueInfo,
   2: optional ACSearchInfo searchInfo,
   3: optional i64 revInfo, // ac serial to be revoked
}

enum ACStatus {
   granted = 0,
   rejection = 1
}

enum ACFailureInfo {
   badAlg = 0,
   badRequest = 2,
   badDataFormat = 5,
   notApproved = 15,
   unacceptedExtension = 16,
   untrustedRequester = 17,
   untrustedHolder = 18,
   unsupportedAttribute = 19,
   unsupportedTemplate = 20,
   unknownSerial = 21,
   systemFailure = 25
}

struct ACStatusInfo {
   1: ACStatus status,
   2: optional ACFailureInfo failInfo,
   3: optional string failText,
}

struct ACResp {
   1: ACStatusInfo statusInfo,
   2: optional list<AttributeCertificate> acs,
}

service AAService 
{
   ACResp request(1:ACReq req)
}



