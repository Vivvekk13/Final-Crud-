<?php

include("connection.php");







if(isset($_GET['id'])){
    $id = $_GET['id'];
     $id = intval($_GET['id']);
    $stmt = $conn->prepare("SELECT `Email2`, `password` FROM `login` WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
} else {
    $row = null;
}





function clean_inputs($field)
{
  $field = trim($field);
  $field = stripslashes($field);
  $field = htmlspecialchars($field);
  return $field;
}

$Name1=$Email1 =$mobile_number1 =$address1="";

$status_ = 0;

$role = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {


  



  $Name = clean_inputs($_POST["Name"]);
  $Email = clean_inputs($_POST["Email"]);
  $address = clean_inputs($_POST["address"]);
  $mobile_number = clean_inputs($_POST["mobile_number"]);
 $password1= clean_inputs($_POST["password1"]);

 $role = clean_inputs($_POST['role'] ?? '');

   


  if (isset($_POST['status_']) && ($_POST['status_'] === '1' || $_POST['status_'] === '0')) {
     $status_ = intval($_POST['status_']);
  } else {
    $status_ = 0;  
  }

  $isValid = true;

  if (!preg_match("/(^[a-zA-Z][a-zA-Z\s]{0,20}[a-zA-Z]$)/", $Name)) {
    $NameErr = "Invalid Name  format";
    $isValid = false;
     $Name1= $_POST["Name"];
   }

   
   

  if (!preg_match("/^[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/", $Email)) {
    $EmailErr = "Invalid Email format";
    $isValid = false;
    $Email1= $_POST["Email"];
  }

  if (!preg_match("/^[0-9]{10}$/", $mobile_number)) {
    $mobile_numberErr = "Invalid mobile_number format";
    $isValid = false;
     $mobile_number1= $_POST["mobile_number"];
  }

    $address1= $_POST["address"];


  if ($role !== 'admin' && $role !== 'client') {
    $roleErr = "Invalid role selected";
    $isValid = false;
}

  if ($isValid) {
    $ins = $conn->prepare("INSERT INTO `notes` (`Name`, `Email`, `mobile_number`, `address`, `password`,`status_`,`role`,`tstamp`) VALUES (?, ?, ?, ?,?,?,?, current_timestamp())");
    $ins->bind_param("sssssis", $Name, $Email, $mobile_number, $address,$password1,$status_,$role);
    $ins->execute();
    $ins->close();

  $lastId2 = $conn->insert_id;
 header("location:http://localhost/vivek/show.php?id={$lastId2}");
   exit;
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
  color: white;
}
#highlight{
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

  <div class="container mt-4" >
    <h2>Employee Details</h2>
    <form action="" method="POST">
      <div class="form-group">
        <label for="Name">Name <span style="color:red">*</span></label>
        <input type="text" class="form-control" id="Name" name="Name" value="<?php echo htmlspecialchars($Name1) ?>" required>
        <?php if ($NameErr) {
          echo $NameErr ;
          
        }
        ?>
      </div>
      <div class="form-group">
        <label for="Email">Email/Username <span style="color:red">*</span></label>
       <input type="text" class="form-control" id="Email" name="Email"
       value="<?php echo htmlspecialchars($row['Email2'] ?? ''); ?>" readonly required>
     <?php if ($EmailErr) {
          echo $EmailErr;
        }
        ?>
      </div>

    <div class="form-group">
        <label for="password">password <span style="color:red">*</span></label>
       <input type="password" class="form-control" id="password1" name="password1"
       value="<?php echo htmlspecialchars($row['password'] ?? ''); ?>" readonly required>
     <?php if ($passwordErr) {
          echo $passwordErr;
        }
        ?>
      </div>


      <div class="form-group">
        <label for="mobile_number">Mobile Number <span style="color:red" >*</span></label>
        <input type="text" class="form-control" id="mobile_number" name="mobile_number" value="<?php echo htmlspecialchars($mobile_number1) ?>" maxlength="10" required>
        <?php if ($mobile_numberErr) {
          echo $mobile_numberErr;
          
        }
        ?>
      </div>

     <div class="form-group">
  <label for="status_">Status <span style="color:red">*</span></label>
  <select class="form-control" id="status_" name="status_" required>
  <option value="1" <?php if ($status_ == 1) echo 'selected'; ?>>Active</option>
  <option value="0" <?php if ($status_ == 0) echo 'selected'; ?>>Inactive</option>
</select>


  <!-- <?php var_dump($status_); ?> -->
</div>



<div class="form-group">
  <label for="role">Role <span style="color:red">*</span></label>
  <select class="form-control" id="role" name="role" required>
    <option value="admin" <?php if (($role ?? '') === 'admin') echo 'selected'; ?>>Admin</option>
    <option value="client" <?php if (($role ?? '') === 'client') echo 'selected'; ?>>Client</option>
  </select>
</div>





      

      <div class="form-group">
        <label for="address">Address <span style="color:red">*</span></label>
        <input type="textarea" class="form-control" id="address" name="address" rows="3" value="<?php echo htmlspecialchars($address1) ?>" required></input>
      </div>
      <button type="submit" class="btn btn-primary">Submit</button>
    </form>
  </div>

  

</body>

</html>
