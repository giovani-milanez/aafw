<?php
namespace aafw\php;

error_reporting(E_ALL);

require_once '/home/giovani/Softwares/thrift-0.9.0/lib/php/lib/Thrift/ClassLoader/ThriftClassLoader.php';
//require_once 'C:\\Desenvolvimento\\thrift-0.9.1\\lib\\php\\lib\\Thrift\\ClassLoader\\ThriftClassLoader.php';

use Thrift\ClassLoader\ThriftClassLoader;

$GEN_DIR = '/home/giovani/workspace-kepler/aafw/gen-php';
//$GEN_DIR = 'C:\\Users\\Gica\\Desktop\\gen-php';

$loader = new ThriftClassLoader();
$loader->registerNamespace('Thrift', '/home/giovani/Softwares/thrift-0.9.0/lib/php/lib');
//$loader->registerNamespace('Thrift', 'C:\\Desenvolvimento\\thrift-0.9.1\\lib\\php\\lib');
$loader->registerDefinition('aafw', $GEN_DIR);
$loader->register();

use Thrift\Protocol\TBinaryProtocol;
use Thrift\Transport\TSocket;
use Thrift\Transport\THttpClient;
use Thrift\Transport\TBufferedTransport;
use Thrift\Exception\TException;

try {
  $socket = new TSocket('localhost', 9090);
  $transport = new TBufferedTransport($socket, 1024, 1024);
  $protocol = new TBinaryProtocol($transport);
  $client = new \aafw\AAServiceClient($protocol);

  $transport->open();

  $entityName["2.5.4.3"] = "testee"; // Common Name 
  $entityName["2.16.76.1.10.1"] = "1"; // Common Name
  $holder = new \aafw\ACHolder(array("entityName" => $entityName));

    // REQUEST TO SEARCH FOR ATTRIBUTE CERTIFICATES ISSUED FOR 'Giovani Milanez'
//  $searchInfo = new \aafw\ACSearchInfo(array("holder" => $holder));
//  $req = new \aafw\ACReq(array("searchInfo" => $searchInfo));

    // REQUEST TO ISSUE AN ATTRIBUTE CERTIFICATE TO 'Giovani Milanez'
    // USING TAMPLATE ID 2

//  $templateId = 10;
//  $reqInfo = new \aafw\ACIssueInfo(array("holder" => $holder, "templateId" => $templateId));
//  $req = new \aafw\ACReq(array("issueInfo" => $reqInfo));

    // REQUEST TO ISSUE AN ATTRIBUTE CERTIFICATE TO 'Giovani Milanez'
    // USING SPECIFIC VALIDITY AND ATTRIBUTE
  $validity = new \aafw\ACValidity(array("notBeforeEpoch" => time(), "notAfterEpoch" => time() + 60 * 60 * 24 * 100 )); // 100 days validity from now
  $attributes[] = new \aafw\Attribute(array("oid" => "1.2.3.4.5", "values" => array("Cinema 3D - Senhor dos Anéis. SALA 5")));
  $reqInfo = new \aafw\ACIssueInfo(array("holder" => $holder, "attributes" => $attributes, "validity" => $validity));
  $req = new \aafw\ACReq(array("issueInfo" => $reqInfo));

  $resp = $client->request($req);

  var_dump($resp);
  
  //file_put_contents("C:\\Users\\Gica\\Desktop\\ac.pem", $resp->acs[0]["pem"], FILE_APPEND | LOCK_EX);  
		 
  $transport->close();

} catch (TException $tx) {
  print 'TException: '.$tx->getMessage()."\n";
}
?>
