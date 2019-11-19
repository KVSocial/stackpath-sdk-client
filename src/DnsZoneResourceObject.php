<?php
namespace StackPath;

/**
DNS Zone resource Object
 **/
class DnsZoneResourceObject
{
    public $id;
    public $name;
    public $type;
    public $ttl;
    public $data;
    public $weight;

    /**
     * Instantiates the Object
     *
     * @returns true
     */
    public function __construct($name, $type, $ttl, $data, $weight, $id = null){
        $this->name = $name;
        $this->validatetypeValue($type);
        $this->ttl = $ttl;
        $this->data = $data;
        $this->weight = $weight;
        if($id != null) {
            $this->id = $id;
        }
    }

    private function validatetypeValue($type) {
        $types = ["EMPTY", "A", "AAAA", "CNAME", "TXT", "MX", "SRV", "NS"];
        if(!in_array($type, $types)) {
            throw new \Exception('type : ' . $type. ' value is not correct');
        }
        $this->type = $type;
    }



}
