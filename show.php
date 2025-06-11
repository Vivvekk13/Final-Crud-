<?php 


include("connection.php");


session_start();
$isAdmin = ($_SESSION['role'] ?? '') === 'admin';


if (isset($_GET['delete'])) {
  $id = $_GET['delete'];
  $dlt = $conn->prepare("UPDATE `notes` SET `is_deleted` = 1 WHERE `id` = ?");
  $dlt->bind_param("i", $id);
  $dlt->execute();
  $dlt->close();
  
  header("location:http://localhost/vivek/show.php?");
}



if (isset($_GET['id']) && isset($_GET['status_'])) {
   $id = intval($_GET['id']);  
       $status_ = intval($_GET['status_']);   
  

        if ($status_ === 1 || $status_ === 0) {
        $stmt = $conn->prepare("UPDATE notes SET status_ = ? WHERE id = ?");
        $stmt->bind_param("ii", $status_, $id);
        $stmt->execute();
        $stmt->close();

         
}
}



// if (isset($_GET['id']) && isset($_GET['role'])) {
//    $id = $_GET['id'];  
//        $role = $_GET['role'];   
  

//         if ($role == "admin" || $role == "client") {
//         $rl = $conn->prepare("UPDATE notes SET role = ? WHERE id = ?");
//         $rl->bind_param("si", $role, $id);
//         $rl->execute();
//         $rl->close();

         
// }

// }


$isAdmin = true;

if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    $checkAdmin = $conn->prepare("SELECT role FROM notes WHERE id = ?");
    $checkAdmin->bind_param("i", $_GET['id']);
    $checkAdmin->execute();
    $result = $checkAdmin->get_result();
    if ($row = $result->fetch_assoc()) {
        $isAdmin = ($row['role'] === 'admin');
    }
    $checkAdmin->close();
}




?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valethi CRUD Operation</title>
     <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css">
</head>
<body>
    


  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <a class="navbar-brand" href="http://localhost/vivek/login.php">
      <img src="valethi.webp " width="50" height="50" alt="">
    </a>

    <a class="navbar-brand" href="http://localhost/vivek/login.php">Valethi Technologies</a>
  </nav>






  <div class="container mt-4">
    <h2>All Employees Details</h2>
    <table class="table table-bordered table-striped">
    <thead class="thead-dark">
  <tr>
    <th>Srno</th>
    <th>Name</th>
    <th>Email/Username</th>
    <th>Mobile Number</th>
    <th>Address</th>
    <th>Status</th>
    <th>Date & Time</th>
    <?php if ($isAdmin): ?>
      <th>Actions</th>
    <?php endif; ?>
  </tr>
</thead>
      <tbody>
<?php
$sql = "SELECT * FROM `notes` WHERE `is_deleted` = 0 ORDER BY id DESC";
$result = mysqli_query($conn, $sql);

while ($row = mysqli_fetch_assoc($result)) {
    $statusText = ($row['status_'] == 1) ? 'Active' : 'Inactive';
    echo "<tr>
        <td>{$row['id']}</td>
        <td>{$row['Name']}</td>
        <td>{$row['Email']}</td>
        <td>{$row['mobile_number']}</td>
        <td>{$row['address']}</td>
        <td>{$statusText}</td>
        <td>{$row['tstamp']}</td>";

    if ($isAdmin) {
        echo "<td>
            <a href='update.php?id={$row['id']}' class='btn btn-success btn-sm'>Edit</a> 
            <a href='?delete={$row['id']}' class='btn btn-danger btn-sm' onclick=\"return confirm('Are you sure?');\">Delete</a>
        </td>";
    }

    echo "</tr>";
}
?>
</tbody>

    </table>
  </div>

</body>
</html>
