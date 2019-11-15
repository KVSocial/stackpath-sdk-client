<?php
namespace StackPath;

/**
Class to store objects in an array
 **/
class Collection
{
    private $items = array();

    public function addItem($obj) {
        $this->items[] = $obj;
    }

    public function toArray() {
        $records = [];
        foreach($this->items as $eachObj) {
            array_push($records, json_decode(json_encode($eachObj), true));
        }
        return $records;
    }

}