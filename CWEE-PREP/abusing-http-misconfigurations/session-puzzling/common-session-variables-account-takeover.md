# Common Session Variables (Account Takeover)

In our final instance, we are going to face a more complex application that more closely showcases how a session puzzling vulnerability may occur in real life. In this case, we cannot simply bypass authentication due to improper handling of the session variable used for authenticating the user. Instead, the session variables are used to store information for two different processes offered by the website and these processes can be combined leading to account takeover. In real engagements, session puzzling vulnerabilities often hide behind a complex series of intertwined processes and we often need to identify them by trial and error if we don't have access to the web application's source code.

## Identification

Just like in the previous sections, we will start by analyzing the web application for the use of session variables to identify possible points of session puzzling. The web application contains processes for user registration and password reset. While doing the user registration process, we can see that it consists of three phases:

```http
http://<SERVER_IP>:<PORT>/register_3.php
```
User Registration Phase 3 page asking to confirm information: Username "testuser", Password, Description "testdescription", Security Question "What is 1+1?", Answer "2", Phone Number "1234567890", Address "12345 Testcity". Includes "Register" button.

Each phase has its own URL at `/register_1.php`, `/register_2.php`, and `/register_3.php`. Attempting to skip ahead and accessing `/register_3.php` directly results in an error message:

```http
http://<SERVER_IP>:<PORT>/index.php
```
Sign-in page with fields for username and password, "Remember me" checkbox, and "Sign in" button. Links for "Register new User" and "Forgot Password?". Warning message: "Please complete Phase 2 first".

When we complete the process of resetting a user's password using the password reset process, we notice that the password reset process also consists of three phases with a similar URL structure. In the third and final phase, we can set a new password for the user:

```http
http://<SERVER_IP>:<PORT>/reset_3.php
```
Password Reset Phase 3 page with input field for new password and "Submit" button.

If the current phase is stored in the session variables, it might be possible to confuse the web application by doing the user registration and password reset concurrently. Just like in the previous sections, we can confirm that the phase is indeed stored in session variables by looking at the network traffic. Let's start by completing the first phase of the password reset process for the provided user. Take note of the session cookie:

```http
HTTP POST request to /reset_1.php on csv_accounttakeover.htb. Includes username htb-stdnt. Response is 302 Found, sets session cookie, and redirects to reset_2.php.
```

Afterward, we attempt to access the second step of the reset phase using an invalid session cookie. The web server responds with an error message indicating that we have not completed phase 1:

```http
HTTP POST request to /reset_2.php on csv_accounttakeover.htb. Includes answer 4 and invalid session cookie. Response is 302 Found, redirects to login.php with message "Please complete Phase 1 first".
```

Now to confirm that our valid session contains the information that we completed the first phase, we can insert our valid session cookie from the first request:

```http
HTTP POST request to /reset_2.php on csv_accounttakeover.htb. Includes answer 4 and session cookie. Response is 302 Found, redirects to reset_3.php.
```

We are now redirected to the third phase. This confirms that the phase is stored in the session variable that corresponds to our session.

## Exploitation

We know that the phase we are currently in is stored in the session variable. For a potential exploit, let's figure out what exactly is an interesting target in the web application. We want to access the admin account, so the password reset functionality seems like the obvious choice. Here is an overview of the three phases:

*   **First phase:** Provide the username
*   **Second phase:** Answer the security question
*   **Third phase:** Reset the password

Since we do not know the answer to the admin account's security question, a potential exploit would be to provide the username in the first step and then skip ahead to the third step to reset the password without ever answering the security question. Doing this directly is not possible due to the phase being stored in the session variable though. However, if the same session variable is re-used to store the phase of the registration process, we could manipulate it to skip the security question with the following sequence of actions:

1.  Do the first phase of the password reset process for the admin account
2.  Complete phases 1&2 of the registration process, marking phases 1&2 complete in our session
3.  Access `/reset_3.php` to set the password of the admin account

Doing so successfully resets the admin password:

```http
HTTP POST request to /reset_3.php on csv_accounttakeover.htb. Includes password newadminpw and session cookie. Response is 302 Found, redirects to login.php.
```

This session puzzling vulnerability is the result of the re-use of the same session variable to store the phase of two different processes. If these processes are executed concurrently, it is possible to skip the security question of the password reset process, thus leading to account takeover.

Let's again look at a simplified code snipped to explain how the vulnerability occurs. The registration process uses the session variable `Phase` to keep track of the phase of the registration process the user is currently in to prevent the user from skipping ahead without completing previous phases. Here is a simplified code snippet from `register_1.php`:

```php
<SNIP>

if(isset($_POST['Submit'])){
    $_SESSION['reg_username'] = $_POST['Username'];  
    $_SESSION['reg_desc'] = $_POST['Description'];  
    $_SESSION['reg_pw'] = $_POST['Password'];  
    $_SESSION['reg_question'] = $_POST['Question'];  
    $_SESSION['reg_answer'] = $_POST['Answer'];  

    $_SESSION['Phase'] = 2;
    header("Location: register_2.php");
    exit;
}

<SNIP>
```

The phase is then checked in the following step `register_2.php`:

```php
<SNIP>

if($_SESSION['Phase'] !== 2){
    header("Location: login.php?msg=Please complete Phase 1 first");
	exit;
};

<SNIP>
```

The vulnerability occurs because the password reset process uses the same session variable `Phase` to keep track of the phase. Thus, it is possible to do the two processes concurrently and skip the security question to reset the admin user's password. Here is a simplified code snippet from `reset_1.php`:

```php
<SNIP>

if(isset($_POST['Submit'])){
	$user_data = fetch_user_data($_POST['Username']);

    if ($user_data) {
		$_SESSION['reset_username'] = $user_data['username'];
        $_SESSION['Phase'] = 2;
        header("Location: reset_2.php");
        exit;
	}
	
	<SNIP>
}

<SNIP>
```


