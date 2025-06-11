<?php

include ("connection.php");
$Email2="";
$EmailErr = "";
$passwordErr = "";
$genErr = "";

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
 }

 if (!preg_match("/^[A-Za-z0-9]{6,}$/", $password1)) {
   $passwordErr = "Invalid password format (minimum 6 characters with at least 1 number)";
   $isValid = false;
 }

 if ($isValid) {
    
    $checkUser = $conn->prepare("SELECT id, password FROM `login` WHERE `Email2` = ?");
    $checkUser->bind_param("s", $Email2);
    $checkUser->execute();
    $result = $checkUser->get_result();
    
    if ($result->num_rows > 0) {
        // User exists 
        $user = $result->fetch_assoc();
        if (password_verify($password1, $user['password'])) {

            $checkUser->close();
            header("location:http://localhost/vivek/show.php?");
            exit;
        } else {
            
            $passwordErr = "Wrong password.";
            $isValid = false;
        }
    } else {
        //  new account
        $hashedPassword = password_hash($password1, PASSWORD_DEFAULT);
        $ins = $conn->prepare("INSERT INTO `login` (`Email2`, `password`) VALUES (?, ?)");
        $ins->bind_param("ss", $Email2, $hashedPassword);
        
        if ($ins->execute()) {
            $lastId = $conn->insert_id;
            $ins->close();
            header("location:http://localhost/vivek/todo.php?id={$lastId}");
            exit;
        } else {
            $genErr = "Error creating account. Please try again.";
        }
    }
    $checkUser->close();
 }
}
?> 

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valethi Employee Login</title>
    
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

    .error-message {
        color: #dc3545;
        font-size: 0.875em;
        margin-top: 0.25rem;
    }

    .success-message {
        color: #28a745;
        font-size: 0.875em;
        margin-top: 0.25rem;
    }
  </style>

<div class="container mt-5"><h2>Valethi Employee Login/Register</h2></div>

  <div class="container mt-5 bg-dark">
  <div class="card mb-3 bg-dark">
    <div class="row g-0 d-flex align-items-center">
      <div class="col-lg-4 d-none d-lg-flex">
        <img src="val.jfif" alt="Valethi Technologies"
          class="w-70 rounded-t-5 rounded-tr-lg-0 rounded-bl-lg-5" />
      </div>
      <div class="col-lg-8">
        <div class="card-body py-5 px-md-5">
          
          <?php if ($genErr): ?>
            <div class="alert alert-danger" role="alert">
              <?php echo $genErr; ?>
            </div>
          <?php endif; ?>

          <form method="POST">
            <div class="form-group">
              <label for="Email">Email/Username <span style="color:red">*</span></label>
              <input type="text" class="form-control" id="Email" name="Email2" 
                     value="<?php echo htmlspecialchars($Email2); ?>" 
                     placeholder="Enter Email" required>
              <?php if ($EmailErr): ?>
                <div class="error-message"><?php echo $EmailErr; ?></div>
              <?php endif; ?>
            </div>
     
            <div class="form-group">
              <label class="form-label" for="form2Example2">Password <span style="color:red">*</span></label>
              <input type="password" id="form2Example2" class="form-control" 
                     name="password1" placeholder="Enter Password" required/>
              <?php if ($passwordErr): ?>
                <div class="error-message"><?php echo $passwordErr; ?></div>
              <?php endif; ?>
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
            
            <button type="submit" id="submit" name="submit" class="btn btn-success btn-sm">
              Login / Register
            </button>
            
            <div class="mt-3">
              <small class="text-muted">
                If you're a new user, an account will be created automatically.
                If you already have an account, you'll be logged in.
              </small>
            </div>
          </form>

        </div>
      </div>
    </div>
  </div>
  </div>
</section>

</body>
</html>
