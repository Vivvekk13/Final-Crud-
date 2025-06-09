<?php


include ("connection.php");
// print_r($_GET);exit;





$id = $_GET['id'] ?? null;

$stmt = $conn->prepare("SELECT * FROM notes WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

$row = $result->fetch_assoc();


$Name1=$Email1 = $mobile_number1 ="";

if($_SERVER['REQUEST_METHOD'] == 'POST'){

  $name=  $_POST['Name'];
  $Email=  $_POST['Email'];

 
  $mobile_number=  $_POST['mobile_number'];


  $address=  $_POST['address'];


  // $new_id = $_GET['id'] ;


   $isValid = true;

   if (!preg_match("/(^[a-zA-Z][a-zA-Z\s]{0,20}[a-zA-Z]$)/", $name)) {
    $NameErr = "Invalid Name  format";
    $isValid = false;
    //  $Name1= $_POST["Name"];
   }
   if (!preg_match("/^[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/", $Email)) {
    $EmailErr = "Invalid Email format";
    $isValid = false;
    // $Email1= $_POST["Email"];
  }

  if (!preg_match("/^[0-9]{10}$/", $mobile_number)) {
    $mobile_numberErr = "Invalid mobile_number format";
    $isValid = false;
    //  $mobile_number1= $_POST["mobile_number"];
  }

 if ($isValid){
  $sql = "UPDATE notes SET Name='$name', Email='$Email', mobile_number='$mobile_number', address='$address' where id='$id' ";



   $result = mysqli_query($conn, $sql);
  //  var_dump($result);

  //  $row= mysqli_fetch_assoc($result);
   


   if($result){
    echo "<script> alert('record updated') </script>";
   
  header("location:http://localhost/vivek/show.php?id={$row['id']}");
   
   }

  }
}








?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Valethi CRUD Operation</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css">
<style>
   body {
    background-image: url('background_img.jpg');
    background-size: cover;
    background-repeat: no-repeat;
    color: white;
}

tr,td,th{
  color: green;
}
</style>

</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
<a class="navbar-brand" href="http://localhost/vivek/login.php">
    <img src="valethi.webp " width="50" height="50" alt="">
  </a>
 
<a class="navbar-brand" href="http://localhost/vivek/login.php">Valethi Technologies</a>
</nav>

<div class="container mt-4">
  <h2>Update Details</h2>
  <form action="" method="POST">
     <div class="form-group">
      <label for="srno  ">Srno</label>
      <input type="hidden" class="form-control" id="id" name="id" value="<?php echo htmlspecialchars($row['id']) ?>" required readonly >
     
    </div>
    <div class="form-group">
      <label for="Name">Name <span style="color:red">*</span></label>
      <input type="text" class="form-control" id="Name" name="Name" value="<?php echo htmlspecialchars($row['Name']) ?>" required>
      <?php if ($NameErr) {
          echo $NameErr ;
          
        }
        ?>
    </div>
    <div class="form-group">
      <label for="Email">Email/Username <span style="color:red">*</span></label>
      <input type="text" class="form-control" id="Email" name="Email" value="<?php echo htmlspecialchars($row['Email'])  ?>" readonly  required>
       <?php if ($EmailErr) {
          echo $EmailErr;
        }
        ?>
    </div>
    <div class="form-group">
      <label for="mobile_number">Mobile Number <span style="color:red">*</span></label>
      <input type="text" class="form-control" id="mobile_number" name="mobile_number"  maxlength="10"  value="<?php echo htmlspecialchars($row['mobile_number']) ?>">
     <?php if ($mobile_numberErr) {
          echo $mobile_numberErr;
          
        }
        ?>
    </div>
    <div class="form-group">
      <label for="address">Address <span style="color:red">*</span></label>
      <input type="textarea" class="form-control" id="address" name="address" rows="3" value="<?php echo htmlspecialchars($row['address'])  ?>" required>
    </div>
    <button type="submit" class="btn btn-primary" id = 'submit' name="submit">Update</button>
  </form>
</div>
    </body>
    </html>