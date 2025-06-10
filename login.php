<?php

include ("connection.php");
 $Email2="";




function clean_inputs($field)
{
  $field = trim($field);
  $field = stripslashes($field);
  $field = htmlspecialchars($field);
  return $field;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

 $Email2 = clean_inputs($_POST["Email2"]);
 $password1 = clean_inputs($_POST["password1"]);
                            
 $isValid = true;

 
  if (!preg_match("/^[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/", $Email2)) {
    $EmailErr = "Invalid Email format";
    $isValid = false;
    $Email2= $_POST["Email2"];
  }


  if (!preg_match( "/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/",$password1)) {
   $passwordErr = "Invalid password format";
    $isValid = false;
    $password1= $_POST["password1"];
  }



 $password1= password_hash($_POST["password1"],PASSWORD_DEFAULT);
 
 if ($isValid) {
    $ins = $conn->prepare("INSERT INTO `login` (`Email2`, `password`) VALUES (?, ?) ");
    $ins->bind_param("ss", $Email2,$password1);
    $ins->execute();
    $ins->close();
    $lastId = $conn->insert_id;
 header("location:http://localhost/vivek/todo.php?id={$lastId}");
   exit;
 
 }

  }
?> 







<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valethi employee login</title>
    
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css">

</head>
<body>

<section class=" text-center text-lg-start">
  <style>
    .rounded-t-5 {
      border-top-left-radius: 0.5rem;
      border-top-right-radius: 0.5rem;
    }

    @media (min-width: 992px) {
      .rounded-tr-lg-0 {
        border-top-right-radius: 0;
      }

      .rounded-bl-lg-5 {
        border-bottom-left-radius: 0.5rem;
      }
    }

     body {
    background-image: url('background_img.jpg');
    background-size: cover;
    background-repeat: no-repeat;
    color: white;
}

  </style>
<div class="container mt-5"><h2>Valethi employee login</h2></div>

  <div class="container mt-5 bg-dark " >
  <div class="card mb-3 bg-dark ">
    <div class="row g-0 d-flex align-items-center ">
      <div class="col-lg-4 d-none d-lg-flex">
        <img src="val.jfif" alt="valethi Technologies"
          class="w-70 rounded-t-5 rounded-tr-lg-0 rounded-bl-lg-5" />
      </div>
      <div class="col-lg-8">
        <div class="card-body py-5 px-md-5">

          <form method="POST">
         <div class="form-group">
        <label for="Email">Email/Username <span style="color:red">*</span></label>
        <input type="text" class="form-control" id="Email" name="Email2" value="<?php $id ?>" placeholder="Enter Email" required>
        <?php if ($EmailErr) {
          echo $EmailErr;
        }
        ?>
      </div>
     
            <div data-mdb-input-init class="form-outline mb-4">
              <input type="password" id="form2Example2" class="form-control" name="password1" placeholder="Enter Password"  required/>
              <label class="form-label" for="form2Example2">Password <span style="color:red">*</span></label>
               <?php if ( $passwordErr) {
          echo  $passwordErr;
        }
        ?>
            </div>

     
            <div class="row mb-4">
              <div class="col d-flex justify-content-center">
          
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" value="" id="form2Example31" checked />
                  <label class="form-check-label" for="form2Example31"> Remember me </label>
                </div>
              </div>

              <div class="col">
            
                <a href="#!">Forgot password?</a>
              </div>
            </div>
   <button type="submit"  id = 'submit' name="submit"  class='btn btn-success btn-sm' >login</button>
          </form>

        </div>
      </div>
    </div>
  </div>
  </div>
</section>

    
</body>
</html>
