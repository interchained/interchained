<?php
class Product
{


    private $table_name = "crypto_payments";

    public $payWallet;


    // create product
    function create($data)
    {

        //write query
        $query = dibi::query('INSERT INTO  ' . $this->table_name . ' %v', $data);

        if ($query)
        {
            return true;
        }
        else
        {
            return false;
        }

    }

    function readOne($data)
    {

        $query = dibi::fetch('SELECT * FROM ' . $this->table_name . ' WHERE address = ?', $data);
        return $query;

        
    }



      function readSingleProduct($data)
    {

        $query = dibi::fetch('SELECT * FROM ' . $this->table_name . ' WHERE orderID = ?', $data);
        return $query;
        
    }



    function update($data, $address)
    {

       dibi::query('UPDATE ' . $this->table_name . ' SET %a', $data, 'WHERE address = ?', $address);

    }




}
?>
