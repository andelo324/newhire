<?php
// Include config file
require_once 'config.php';
 
// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = "";
 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Check if username is empty
    if(empty(trim($_POST["username"]))){
        $username_err = 'Please enter username.';
    } else{
        $username = trim($_POST["username"]);
    }
    
    // Check if password is empty
    if(empty(trim($_POST['password']))){
        $password_err = 'Please enter your password.';
    } else{
        $password = trim($_POST['password']);
    }
    
    // Validate credentials
    if(empty($username_err) && empty($password_err)){
        // Prepare a select statement
        $sql = "SELECT username, password FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            
            // Set parameters
            $param_username = $username;
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Store result
                mysqli_stmt_store_result($stmt);
                
                // Check if username exists, if yes then verify password
                if(mysqli_stmt_num_rows($stmt) == 1){                    
                    // Bind result variables
                    mysqli_stmt_bind_result($stmt, $username, $hashed_password);
                    if(mysqli_stmt_fetch($stmt)){
                        if(password_verify($password, $hashed_password)){
                            /* Password is correct, so start a new session and
                            save the username to the session */
                            session_start();
                            $_SESSION['username'] = $username;      
                            header("location: welcome.php");
                        } else{
                            // Display an error message if password is not valid
                            $password_err = 'The password you entered was not valid.';
                        }
                    }
                } else{
                    // Display an error message if username doesn't exist
                    $username_err = 'No account found with that username.';
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }
        }
        
        // Close statement
        mysqli_stmt_close($stmt);
    }
    
    // Close connection
    mysqli_close($link);
}
?>










<!DOCTYPE html>
<html lang="en" >

<head>
  <meta charset="UTF-8">
  <title>Rubie's New Hire Login</title>
  
  
  
      <link rel="stylesheet" href="css/login.css">
      <link rel="stylesheet" type="text/css" href="css/main.css">
      <link rel="stylesheet" type="text/css" href="css/bootstrap.css">

  
</head>

<body>

  <body>
<div class="container">
			
			<h1 class="text-center" id="firstWord">Rubie's Costume Co<span id="secondWord"> New Hire Form</span><a  href="http://www.rubieshelp.com"><img alt="Brand" src="img/index_logo.png" width="40px" height="40px"></a></h1>

	</div>
	<hr />
	<br>


	<div class="login">
		<div class="login-screen">
			<div class="app-title">
				<h1>Login</h1>
			</div>

<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
			<div class="login-form">
				<div class="control-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
				<input type="email" name="username" class="login-field" value="" placeholder="email address" id="login-name" value="<?php echo $username; ?>">
				<span class="help-block"><?php echo $username_err; ?></span>
				<label class="login-field-icon fui-user" for="login-name"></label>
				</div>

				<div class="control-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
				<input type="password" name="password" class="login-field" value="" placeholder="password" id="login-pass">
				<label class="login-field-icon fui-lock" for="login-pass"></label>
				</div>
				
				<input type="submit" class="btn btn-primary btn-large btn-block" value="Login">login</a>
				<!-- <a class="login-link" href="#">Lost your password?</a> -->
			</div>
		</div>
	</div>
</form>
</body>
  
  

</body>

</html>
