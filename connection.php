<?php
$servername = "localhost";
$username = "root";
$password = "";
$database = "notes";


$Name = $Email = $address = $mobile_number= $password1="";
$NameErr = $EmailErr = $mobile_numberErr =$passwordErr= "";

$conn = mysqli_connect($servername, $username, $password, $database);
if (!$conn){
    die("Connection failed: " . mysqli_connect_error());
}
?>