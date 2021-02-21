<?php
namespace StackPath;

/**
Stackpath SDK v0.5
SDK to communicate with Stackpath.com API

@author Steven van der Peijl for https://kyvio.com

Requires
- Guzzle client
- Config var example:
$stackPath = [
    'stack_id' => '',
    'client_id' => '',
    'secret_id' => '',
    'ip_to_map' => '',
    'waf_options_off' => ['CSRF', 'Anti Scraping'],
]

Forked from https://github.com/newsdaycom/stackpath-php-sdk/
**/
class StackPath
{
    public $gateway = "https://gateway.stackpath.com";
    public $config = [];
    public $statuscode = false; //to get statuscode from last call
    public $allsites = false; //buffer due to poor API design
    public $debug ='';
    /**
    * Instantiates the client
    *
    * @param array $config Config variable array. Must have keys 'stack_id', 'client_id', 'secret_id' and 'ip_to_map'. Obligatory
    * @returns true
    */
    public function __construct(array $config){
        if(!isset($config['stack_id']) || !isset($config['client_id']) || !isset($config['secret_id']) || !isset($config['ip_to_map'])){
            throw new \Exception('Missing stackpath config values');    
        }
        
        /** Instantiates Guzzle client with gateway as default root */
        $this->client = new \GuzzleHttp\Client([
          "base_uri" => $this->gateway,
          "timeout" => 120
        ]);
        
        $this->config = $config;
        //$this->debuglog('Config: ');
        //$this->debuglog(print_r($this->config,true));
        
        /** Retrive the auth token on instantiation */
        $params = [ \GuzzleHttp\RequestOptions::JSON => [
                    'client_id' => $this->config["client_id"], 
                    'client_secret' => $this->config["secret_id"], 
                    'grant_type' => "client_credentials"
                ] 
            ];        
        $tokenres = $this->post("/identity/v1/oauth2/token",$params);
        //$tokenres = $this->post("/identity/v1/oauth2/token", ["json" => [
        //  "client_id" => $this->config["client_id"],
        //  "client_secret" => $this->config["secret_id"],
        //  "grant_type" => "client_credentials"
        //]]);
        
        if(empty($tokenres)){
            throw new \Exception(__LINE__.' Empty response from SP api. Response: \n');
        } 
        elseif(empty($tokenres->access_token)){
            throw new \Exception(__LINE__.' Bad response '.$this->statuscode.' from SP api. Response: \n');
        }
        else{
            $this->token = $tokenres->access_token;
        }
        return true;
    }
    
    
    /**
    * @param string $domain domain to create CDN site for. Obligatory
    * @param array $options array with site options to active e.g ['CDN', 'WAF']. By default only CDN is created
    * @returns object SP API JSON decoded response object is returned
    **/
    public function createCDNsite($domain, $options = ['CDN']){
        $params = [ \GuzzleHttp\RequestOptions::JSON => [
                    'domain' => $domain, 
                    'features' => $options, 
                    'origin' => [
                        'path' => '/',
                        'hostname' => $this->config['ip_to_map'],
                        'port' => 80
                    ]
                ] 
            ];

        $response = $this->post('/cdn/v1/stacks/'.$this->config['stack_id'].'/sites',$params);                
        if(empty($response) || !is_object($response)){
            throw new \Exception(__LINE__.' Empty response from SP api creating CDN site for '.$domain. ' Response: '.var_dump($response,true));
        } 
        elseif(property_exists($response, "site")){
            if(property_exists($response->site, "id")) {
                $site = $response->site;
                $siteId = $site->id;
                $existingsitedata = $this->getCDNCertData($siteId,$domain);
                $existingsitedata['cdn_url'] = $this->getCnameForSite($siteId);
                $existingsitedata['site_id'] = $siteId;
                $existingsitedata['site_exists'] = 1;
                $existingsitedata['status'] = "stackpath_call_done";
                $response = (object) $existingsitedata;
                return $response;
            }
            else{
                throw new \Exception(__LINE__.' Bad  response from SP api creating CDN site for '.$domain. ' Response: '.var_dump($response,true));
            }
        }
        else{
            //all is good
            return $response;    
        }
    }
    
    /**
    * @param string $domain domain for the WAF site to be created obligatory
    * @param string $sp_site_id the SP site id string optional. Set if WAF is related to existing CDN site
    * @param object $origin Origin settings. Optional. Set if you want to create standalone WAF site
    * @returns object API JSON decoded response object is returned
    **/
    public function createWAFSite($domain, $sp_site_id = false, $origin = false){
        if($sp_site_id == false && is_object($origin) ){
            //create standalone WAF site
            $params = [ \GuzzleHttp\RequestOptions::JSON => [
                                'name' => $domain,
                                'origin' => $origin
                            ] 
                      ];        
        }
        elseif($sp_site_id != false){
            //create WAF site connected with CDN site
            $params = [ \GuzzleHttp\RequestOptions::JSON => [
                                'name' => $domain, 
                                'deliveryId' => $sp_site_id
                            ] 
                      ];
        }
        else{
            //missing data!
            throw new \Exception('Missing either SP site ID or Origin data for WAF site creation');    
        }
            
        $response = $this->post('/waf/v1/stacks/'.$this->config['stack_id'].'/sites',$params);
        if(empty($response)){
            throw new \Exception(__LINE__.'Empty response from SP api creating WAF site for '.$domain);
        }
        elseif(empty($response->site)){
            throw new \Exception(__LINE__.' Bad  response from SP api creating WAF site for '.$domain. ' Response: '.var_dump($response,true));   
        } 
        else{
            return $response;    
        }      
    }
    
    /**
    * @param string $waf_site_id  SP waf site id obligatory
    * @param array $on array of policy names that need to be turned ON. Optional
    * @param array $off array of policy names that need to be turned OFF. Optional
    * @returns array Array with issues enabling/disabling WAF options. If empty all is good.
    **/
    public function setWAFoptions($waf_site_id, $on = array(), $off= array() ){
        if(count($on) < 1 && count($off) < 1){
            throw new \Exception('Missing data, at least include on / off data to set WAF options');    
        }
        
        $responseWafPolicies = $this->get('/waf/v1/stacks/'.$this->config['stack_id'].'/sites/'.$waf_site_id.'/policy_groups',[]);
        if(empty($responseWafPolicies) ){
            throw new \Exception('Invalid response from SP api getting WAF options for WAF site id: '.$waf_site_id);
        }
        
        $alloptions = array_merge($on,$off);
        $tc = count($alloptions);$c = 0;$issues = [];
        foreach ($responseWafPolicies->policyGroups as $policyGroup) {
            foreach ($policyGroup->policies as $policy) {
                if(in_array($policy->name,$on)){
                    $this->post('/waf/v1/stacks/' . $this->config['stack_id'].'/sites/'. $waf_site_id .'/policy_groups/'.$policyGroup->id.'/policies/'.$policy->id.'/enable',[]);
                    if($this->statuscode != "204"){
                        $issues[] = $policy->name. " not enabled";    
                    }
                    $c++;
                }
                elseif(in_array($policy->name, $off)){
                    // Disable policy
                    $this->post('/waf/v1/stacks/' . $this->config['stack_id'].'/sites/'. $waf_site_id .'/policy_groups/'.$policyGroup->id.'/policies/'.$policy->id.'/disable',[]);
                    if($this->statuscode != "204"){
                        $issues[] = $policy->name. " not disabled";    
                    }
                    $c++;
                }
                if($c == $tc){
                    //all options to be turned on/off are set already stop wasting time and move on
                    break 2;    
                }                
            }
        }    
        return $issues;   
    }
    
    /**
    * @param string $sp_site_id  SP site ID string obligatory
    * @returns string the SP hostname value for the domain CNAME mapping
    **/
    public function getCnameForSite($sp_site_id){
        //get CNAME for domain:
        $responseCdn = $this->get('/cdn/v1/stacks/'.$this->config['stack_id'].'/sites/'.$sp_site_id.'/dns/targets',[]);
        if(empty($responseCdn->addresses)){
            throw new \Exception(__LINE__.'Invalid response from SP api getting CDN url for Site ID: '.$sp_site_id. ' Response: '.var_dump($responseCdn,true));    
        }
        return $responseCdn->addresses[0];        
    } 
    
    /**
    * @param string $domain  domain for which to create ssl
    * @param string $sp_site_id  SP site id string
    * @return array array with cert data. Must have keys 'host', 'value' and 'cert_id' for success
    **/
    public function createSSLCert($domain, $sp_site_id){
        $certdata = [];
        
        //create CERT request
        $cert = [ \GuzzleHttp\RequestOptions::JSON => [
                        'hosts' => [$domain] 
                    ] 
                ];
        
        $responseCert = $this->post('/cdn/v1/stacks/'.$this->config['stack_id'].'/sites/'.$sp_site_id.'/certificates/request',$cert);
        if(empty($responseCert->verificationRequirements) ) {
            throw new \Exception('Invalid response from SP api requesting SSL CERT for '.$domain. ' Response: '.var_dump($responseCert,true));    
        } 
            
        //get CERT DNS records
        $data = $responseCert->verificationRequirements[0]->dnsVerificationDetails->dnsRecords[0];
        $dataParts = explode(' ', $data);
        $certdata['host'] = $dataParts[0];
        $certdata['value'] = $dataParts[4];
        $certdata['cert_id'] = $responseCert->certificate->id;    
        return $certdata;
    }
    
    /**
    * @param string $cdn_site_id CDN site ID string from SP. Obligatory 
    * @param string $domain The domain in case we need to do retry on SSL generation
    * @return array Array with key-values for SSL CNAME data. Keys: host, value, cert_id
    **/    
    public function getCDNCertData($cdn_site_id, $domain){
        $existingsitedata = [];
        
        //ok now the cert DNS..
        $certs = $this->get('/cdn/v1/stacks/'.$this->config['stack_id'].'/sites/'.$cdn_site_id.'/certificates',[]);
        if(empty($certs->results)){
            //this happens if there is no CERT data set (failed / expired)
            //so what we need here is retry of CERT data
            //throw new \Exception(__LINE__.' Empty response from SP api creating CDN site for site id: '.$cdn_site_id. ' Response: '.var_dump($certs,true));   

            $existingsitedata = $this->createSSLCert($domain, $cdn_site_id);
        }
        else{ 
            //not sure why it can be multiple but just only taking first.
            $certid = $certs->results[0]->certificate->id;  
                        
            $certscname = $this->get('/cdn/v1/stacks/'.$this->config['stack_id'].'/certificates/'.$certid.'/verification_details',[]);                 
            if(empty($certscname->verificationRequirements)){
                //if SSL is all good and setup this can happen
                //happens in situations where did it manually
                //throw new \Exception(__LINE__.' Missing data from siteID: '.$cdn_site_id.' CertID: '.$certid.' Response: '.var_dump($certscname,true).' '.var_dump($certs,true));   
                $existingsitedata['cert_id'] = $certid;
            }
            else{ 
                $data = $certscname->verificationRequirements[0]->dnsVerificationDetails->dnsRecords[0];
                $dataParts = explode(' ',$data);
                $existingsitedata['host'] = $dataParts[0];
                $existingsitedata['value'] = $dataParts[4];
                $existingsitedata['cert_id'] = $certid;
            }
        }
        return $existingsitedata;     
    }
    
    /**
     * @param INT $page_request_first The number of items desired.
     * @param INT $page_request_after The cursor value after which data will be returned.
     * @param string $page_request_filter SQL-style constraint filters.
     * @param string $page_request_sort_by Sort the response by the given field.
     * @returns array $allcdnsites Array with as keys the hostnames and as value an array with all data from the API
    **/
    public function getAllCDNSites($page_request_first = "", $page_request_after = "", $page_request_filter = "", $page_request_sort_by = "" ){
            $queryParams = [];
            $addParams = "";
            if(is_numeric($page_request_first)) {
                $queryParams[] = "page_request.first=" . $page_request_first;
            }
            if(is_numeric($page_request_after)) {
                $queryParams[] = "page_request.after=" . $page_request_after;
            }
            if($page_request_filter != "") {
                $queryParams[] = "page_request.filter=" . $page_request_first;
            }
            if(is_numeric($page_request_sort_by)) {
                $queryParams[] = "page_request.sort_by=" . $page_request_sort_by;
            }
            if(count($queryParams) > 0) {
                $addParams = "?" . implode("&", $queryParams);
            }
            $response = $this->get('/cdn/v1/stacks/'.$this->config['stack_id'].'/sites' . $addParams,[]);
            if(empty($response)){
                throw new \Exception(__LINE__.'Empty response from SP api listing  DNS Zones.');
            }
            else{
                return $response;
            }


    }
    
    /**
    * @param string $cdn_site_id site ID string from SP API
    * @returns boolean true if deleted, false if not
    */    
    public function deleteCDNSite($cdn_site_id, $options = []){
        $this->delete('/cdn/v1/stacks/'.$this->config['stack_id'].'/sites/'.$cdn_site_id, $options);
        if($this->statuscode == "204"){
            return true;
        }
        else{
            return false;    
        }
    }
    
    /**
    * @param string $waf_site_id  site ID string from SP API
    * @returns boolean true if deleted, false if not
    */
    public function deleteWAFSite($waf_site_id){
        $this->delete('/waf/v1/stacks/'.$this->config['stack_id'].'/sites/'.$waf_site_id, []);
        if($this->statuscode == "204"){
            return true;
        }
        else{
            return false;    
        }
    }
    
    /**
    * @param string $cert_id cert ID string from SP API. Obligatory
    * @param string $type 'cdn' or 'waf' to delete either CDN or WAF cert. Default is 'cdn'. Optional.
    * @returns boolean true if deleted, false if not
    */
    public function deleteCert($cert_id, $type = 'cdn'){
        $this->delete('/'.$type.'/v1/stacks/'.$this->config['stack_id'].'/certificates/'.$cert_id, []);
        if($this->statuscode == "204"){
            return true;
        }
        else{
            return false;    
        }        
    }

    /**
     * @param string $domain The name of the DNS zone's domain.
     * @param boolean $useApexDomain Whether or not to create a zone for the apex domain only.
     * If this is true and a domain with subdomains is provided, it will be stripped and only the root domain will be used for the zone. If this is false an error will be returned if it's not already an apex domain.
     * @returns object API JSON decoded response object is returned
     **/
    public function createDNSZone($domain, $useApexDomain = true){
            $params = [ \GuzzleHttp\RequestOptions::JSON => [
                'stackId' => $this->config['stack_id'],
                'domain' => $domain,
                'useApexDomain' => $useApexDomain
            ]
            ];
            $response = $this->post('/dns/v1/stacks/'.$this->config['stack_id'].'/zones',$params);
            if(empty($response)){
                throw new \Exception(__LINE__.'Empty response from SP api creating DNS Zone for '.$domain);
            }
            elseif(empty($response->zone)){
                throw new \Exception(__LINE__.' Bad  response from SP api creating DNS Zone for '.$domain. ' Response: '.var_dump($response,true));
            }
            else{
                return $response;
            }
    }

    /**
    * search CDN site By Domain
    * @access public
    * @param string $domain domain to search CDN site for. Obligatory
    * @returns array SP API JSON decoded response array is returned
    **/
    public function searchCDNsiteByDomain($domain){
        $totapicount = 10; // Normally one api call to list matching domain is enough, We try 10 api calls max, will update this in code based on response
        $batch = 20; // each api call will have 20 sites max in result
        $totc = 0;$runs = 0;
        $matchingCdnSites = [];
        while($totapicount > 0){
            $totapicount--;
            $runs++;
            $url = '/cdn/v1/stacks/'.$this->config['stack_id'].'/sites?'."page_request.filter=scopes.hostnames.domain='".$domain."'&page_request.first=".$batch;
            if($runs  > 1){ // after first api call append this too
                $url .= '&page_request.after='.$totc;
            }
            $response = $this->get($url, []);
            if(!empty($response->results) ) {
                if($runs == 1){
                    $totalCount = $response->pageInfo->totalCount;
                    if(!is_numeric($totalCount)){
                        throw new \Exception('Code/API error - Response: ');    
                    }
                    $totapicount = ceil($totalCount/$batch); //Set total api call count
                }
                // Now loop over each entry
                foreach($response->results as $k => $site){
                    $matchingCdnSites[$site->label] = (array) $site;
                    $totc++;
                }
                if(count($response->results) < $batch){ // Get out of the loop
                    $totapicount = 0;
                }
            }
            else{
                $totapicount = 0; // Get out of the loop
                if($runs == 1){
                    throw new \Exception(__LINE__.'API error - empty Response: ');    
                }                
            }
            if($totapicount > 0){
                sleep(1); //sleep 1 seconds to not kill the API
            }
        }
        return $matchingCdnSites;
    }

    /**
     * Retrieve all DNS zones on a stack or for a domain
     * @param string $domain The name of the DNS zone's domain.(Optional)
     * @param $page_request_first The number of items desired.
     * @param $page_request_after The cursor value after which data will be returned.
     * @param $page_request_filter SQL-style constraint filters.
     * @param $page_request_sort_by Sort the response by the given field.
     * @returns object API JSON decoded response object is returned
     **/
    public function listDNSZones($domain = "", $page_request_first = "", $page_request_after = "", $page_request_filter = "", $page_request_sort_by = "" ){
           $queryParams = [];
            $addParams = "";
           if(is_numeric($page_request_first)) {
               $queryParams[] = "page_request.first=" . $page_request_first;
           }
            if(is_numeric($page_request_after)) {
                $queryParams[] = "page_request.after=" . $page_request_after;
            }
            if($page_request_filter != "") {
                $queryParams[] = "page_request.filter=" . $page_request_filter;
            }
            if(is_numeric($page_request_sort_by)) {
                $queryParams[] = "page_request.sort_by=" . $page_request_sort_by;
            }
            if(count($queryParams) > 0) {
                $addParams = "?" . implode("&", $queryParams);
            }
            $response = $this->get('/dns/v1/stacks/'.$this->config['stack_id'].'/zones' . $addParams,[]);
            if(empty($response)){
                throw new \Exception(__LINE__.'Empty response from SP api listing  DNS Zones.');
            }
            elseif(empty($response->zones)){
                throw new \Exception(__LINE__.' No DNS Zones Found');
            }
            else{
                if($domain != "") {
                    $zones = $response->zones;
                    $foundZone = false;
                    foreach($zones as $eachZone) {
                        if($eachZone->domain == $domain) {
                            $foundZone = true;
                            return $eachZone;
                        }
                    }
                    if(!$foundZone) {
                        throw new \Exception(__LINE__.' No DNS Zones Found for domain' . $domain);
                    }
                }
                return $response;
            }
    }

    /**
     * Delete DNS Zone for a domain
     * @param string $domain The name of the DNS zone's domain.
     * @returns boolean true if deleted, false if not
     */
    public function deleteDNSZone($domain){
            if($domain != "") {
                $zone_id = $this->getDNSZone($domain);
                if($zone_id != "") {
                    $this->delete('/dns/v1/stacks/'.$this->config['stack_id'].'/zones/'.$zone_id, []);
                    if($this->statuscode == "204"){
                        return true;
                    }
                    else{
                        return false;
                    }
                }
                else {
                    throw new \Exception(__LINE__.' Zone not found');
                }
            }
            else {
                throw new \Exception(__LINE__.' Domain value is empty');
            }
    }

    /**
     * Get DNS Zone Id for a domain
     * @param string $domain The name of the DNS zone's domain.
     * @returns integer Zone Id
     */
    public function getDNSZone($domain){
            if($domain != "") {
                $getZoneInfo = $this->listDNSZones($domain, "", "","domain='".$domain."'");
                if(isset($getZoneInfo->id)) {
                    $zone_id = $getZoneInfo->id;
                    return $zone_id;
                }
                else {
                    throw new \Exception(__LINE__.' Zone not found');
                }
            }
            else {
                throw new \Exception(__LINE__.' Domain value is empty');
            }
    }

    /**
     * Create/Update multiple DNS zone resource records for a domain
     * @param string $domain The name of the DNS zone's domain.
     * @param $records The records to create or update in the DNS zone.
     **/
    public function createMultipleDNSZoneRecords($domain, $records = null){
            if($domain != "") {
                $getZoneInfo = $this->listDNSZones($domain, "", "","domain='".$domain."'");
                if(isset($getZoneInfo->id)) {
                    $zone_id = $getZoneInfo->id;
                    $params = [ \GuzzleHttp\RequestOptions::JSON => [
                        'records' => $records
                    ]
                    ];
                    $response = $this->post('/dns/v1/stacks/' . $this->config['stack_id'] . '/zones/' . $zone_id . '/bulk/records', $params);
                    if(empty($response)){
                        throw new \Exception(__LINE__.'Empty response from SP api creating Multiple DNS Zone Records for '.$domain);
                    }
                    else{
                        return $response;
                    }
                }
                else {
                    throw new \Exception(__LINE__.' Zone not found');
                }
            }
            else {
                throw new \Exception(__LINE__.' Domain value is empty');
            }
    }

    /**
     * Retrieve a DNS zone's resource records via domain
     * @param string $domain The name of the DNS zone's domain.(Optional)
     * @param $page_request_first The number of items desired.
     * @param $page_request_after The cursor value after which data will be returned.
     * @param $page_request_filter SQL-style constraint filters.
     * @param $page_request_sort_by Sort the response by the given field.
     * @returns object API JSON decoded response object is returned
     **/
    public function listDNSZonesRecords($domain, $page_request_first = "", $page_request_after = "", $page_request_filter = "", $page_request_sort_by = "" ){
            if($domain != "") {
                $getZoneInfo = $this->listDNSZones($domain, "", "","domain='".$domain."'");
                if(isset($getZoneInfo->id)) {
                    $zone_id = $getZoneInfo->id;
                    $queryParams = [];
                    $addParams = "";
                    if(is_numeric($page_request_first)) {
                        $queryParams[] = "page_request.first=" . $page_request_first;
                    }
                    if(is_numeric($page_request_after)) {
                        $queryParams[] = "page_request.after=" . $page_request_after;
                    }
                    if($page_request_filter != "") {
                        $queryParams[] = "page_request.filter=" . $page_request_first;
                    }
                    if(is_numeric($page_request_sort_by)) {
                        $queryParams[] = "page_request.sort_by=" . $page_request_sort_by;
                    }
                    if(count($queryParams) > 0) {
                        $addParams = "?" . implode("&", $queryParams);
                    }
                    $response = $this->get('/dns/v1/stacks/' . $this->config['stack_id'] . '/zones/' . $zone_id . '/records' . $addParams,[]);
                    if(empty($response)){
                        throw new \Exception(__LINE__.'Empty response from SP api listing  DNS Zones Records.');
                    }
                    else{
                        return $response;
                    }
                }
                else {
                    throw new \Exception(__LINE__.' Zone not found');
                }
            }
            else {
                throw new \Exception(__LINE__.' Domain value is empty');
            }
    }

    /**
     * Scan a domain name for information about its provider
     * @param string $domain The domain name to scan for provider information
     * @returns object API JSON decoded response object is returned
     **/
    public function scanDomain($domain){
            if($domain != "") {
               $response = $this->get('dns/v1/discovery/' . $domain . '/provider_details',[]);
               if(empty($response)){
                  throw new \Exception(__LINE__.'Empty response from SP api scanning domain' . $domain);
               }
               else{
                  return $response;
               }
            }
            else {
                throw new \Exception(__LINE__.' Domain value is empty');
            }
    }

    /**
     * Scan a domain name for its resource records
     * @param string $domain The domain name to scan for provider information
     * @returns object API JSON decoded response object is returned
     **/
    public function scanDomainForRecords($domain, $dnsProvider = "GENERAL", $authenticationUser = "", $apiKey = ""){
            if($domain != "") {
                $params = [ \GuzzleHttp\RequestOptions::JSON => [
                    'dnsProvider' => $dnsProvider,
                    'authenticationUser' => $authenticationUser,
                    'apiKey' => $apiKey
                ]
                ];
                $response = $this->post('dns/v1/discovery/' . $domain . '/records',$params);
                if(empty($response)){
                    throw new \Exception(__LINE__.'Empty response from SP api scanning domain for resource records' . $domain);
                }
                else{
                    return $response;
                }
            }
            else {
                throw new \Exception(__LINE__.' Domain value is empty');
            }
    }



    /**
    * Shorthand method for GET requests
    *
    * @param String $url relative or absolute URL
    * @param Array $payload Data being sent to the API
    */
    public function get($url, $payload)
    {
        return $this->request([
          "url" => $url,
          "method" => "GET",
          "payload" => $payload
        ]);
    }
    
    /**
    * Shorthand method for POST requests
    *
    * @param String $url relative or absolute URL
    * @param Array $payload Data being sent to the API
    */
    public function post($url, $payload){
        $res = $this->request([
          "url" => $url,
          "method" => "POST",
          "payload" => $payload
        ]);
        
        return $res;
    }
    
    /**
    * Shorthand method for DELETE requests
    *
    * @param String $url relative URL
    * @param Array $payload Data being sent to the API
    */
    public function delete($url, $payload)
    {
        return $this->request([
          "url" => $url,
          "method" => "DELETE",
          "payload" => $payload
        ]);
    }
    
    /**
    * Purges files from StackPath CDN
    *
    * Maps $files array to object for removal
    * @param Array $files full URLs to paths for removal
    */
    public function purge_files($fileList, $opts = [])
    {
        $stack_id = $this->config["stack_id"];
        $files = [];
        $opts = array_merge(["recursive" => true,], $opts);
        foreach ($fileList as $file) {
            $files[] = array_merge($opts, ["url" => $file]);
        }
        $purge_id = $this->post("cdn/v1/stacks/{$stack_id}/purge", ["json" => [
          "items" => $files,
        ]]);
    }
    
    /**
    * Shorthand method for PUT requests
    *
    * @param String $url relative URL
    * @param Array $payload Data being sent to the API
    */
    public function put($url, $payload)
    {
        return $this->request([
          "url" => $url,
          "method" => "PUT",
          "payload" => $payload
        ]);
    }
    
    /**
    * Shorthand method for PATCH requests
    *
    * @param String $url relative URL
    * @param Array $payload Data being sent to the API
    */
    public function patch($url, $payload)
    {
        return $this->request([
          "url" => $url,
          "method" => "PATCH",
          "payload" => $payload
        ]);
    }    
    
    /**
    * Universal method for sending requests to StackPath
    *
    * @param Array $opts All of the request options
    * @returns object Returns object either API response object or exception object
    */
    public function request($opts = []){
        
        /**
        * Default values can be overridden by defining them in the $opts passed to request
        */
        $default_options = [
          /** Payload is this library's term for all of the data being sent to the API */
          "payload" => [
            /** Unless overridden, every payload will send the Accept header set to application/json */
            "headers" => [
              'Accept' => 'application/json'
            ]
          ]
        ];
        
        /**
        * Recursive merge of custom options over defaults
        */
        $opts = array_merge_recursive($default_options, $opts);
        
        /**
        * Method MUST be defined in the opts sent over
        */
        if (isset($opts["method"])) {
            $method = $opts["method"];
        } else {
            die("Please provide a method for your request");
        }
        
        /**
        * URL MUST be defined in the opts sent over
        */
        if (isset($opts["url"])) {
            $url = $opts["url"];
        } else {
            die("Please provide a url for your request");
        }
        
        $payload = $opts["payload"];
        
        /** Honors debug mode set above */
        $payload['debug'] = $this->debug;
        
        /** If the bearer token has been retrieved, supply it as the auth header */
        if (isset($this->token)) {
            $payload["headers"]["Authorization"] = sprintf("Bearer %s", $this->token);
        }
        
        /** Default payload options. Can be overriden by defining them in $opt["payload"] when supplied to this method */
        $payload_defaults = [
          "allow_redirects" => true,
            'timeout' => 180,
            'connect_timeout' => 180
        ];
        if(isset($payload['allow_redirects'])){
            unset($payload_defaults['allow_redirects']);
        }
        if(isset($payload['timeout'])){
            unset($payload_defaults['timeout']);
        }
        if(isset($payload['connect_timeout'])){
            unset($payload_defaults['connect_timeout']);
        }
        $payload = array_merge_recursive($payload_defaults, $payload);
        $res = false;$success = false;
        try {
            /** Fires the request */
            $res = $this->client->request($method, $url, $payload);
            $this->statuscode = $res->getStatusCode();
            $success = true;
        } 
        catch(\Exception $e) { //RequestException
            // If there are network errors, we need to ensure the application doesn't crash.
            // if $e->hasResponse is not null we can attempt to get the message
            // Otherwise, we'll just pass a network unavailable message.
            $res = $e;
            $exception = false;
            if ($e->hasResponse()) {
                $exception = (string) $e->getResponse()->getBody();
                $res = json_decode($exception);
                $this->statuscode = $e->getCode(); //http code
            } 
        }
        $response = false;
        if(is_object($res) && $success == true){
            if($res->getBody()){
                //weirdes shit ever if you just return $res and then move 
                //this line in another method it stops working...
                $response = json_decode($res->getBody()->getContents());
            }
            else{
                if(!empty($res->message)) {
                    throw new \Exception($res->message);
                }
                throw new \Exception(__LINE__.'Empty response from SP API.');
            }
        }
        else{
            if(!empty($res->message)) {
                throw new \Exception($res->message);
            }
            if(method_exists($res, "getMessage")){
                throw new \Exception(__LINE__.$res->getMessage());
            }
            else{
                throw new \Exception(__LINE__.'Empty response from SP API.');
            }

        }       
        return $response;
    }
}
