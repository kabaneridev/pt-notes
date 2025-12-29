# Premature Session Population (Auth Bypass)

The second instance of session puzzling does not result from common session variables as in the previous example but rather from the premature population of session variables. This means that the web server stores data in the session variables before a process is entirely complete or before the result of the process is known. In our example case, this leads to an authentication bypass.

## Identification

When starting the exercise below we are greeted with a slightly altered application from the previous section. The Forgot Password? functionality has been stripped, so the web application is less complex.

Let's start by analyzing the login process since we already know that the login process stores data in session variables. After a successful login, we are redirected to /profile.php which displays account information like in the previous section. However, the login flow for a failed login attempt is slightly different. We are redirected to /login.php?failed=1 and the login page displays an error message:

```http
http://<SERVER_IP>:<PORT>/
```
Sign-in page with fields for username and password, "Remember me" checkbox, and "Sign in" button. Warning message: "Login failed for user admin".

This is interesting, as the redirect results in a separate request to which the response contains the username sent in the login request. Since the request triggered by the redirect does not contain the username in any parameter, we can deduce that the web server stores the user in session variables. We can confirm this, by sending a request to /login.php?failed=1 without a valid session cookie and observe how the error message changes:

```http
HTTP GET request to /login.php?failed=1 on psp_authbypass.htb. Response includes HTML with a dismissible alert: "Warning! Login failed for user!".
```

We can see that the error message changed and does not contain a username anymore. This confirms that session variables are used to store the user, even for a failed login attempt.

## Exploitation

We identified that the session variables are populated even when the login attempt fails. If the web server does not properly clean up the session variable, we should therefore be able to access the post-login page even after a failed login attempt. However, sending a request to /profile.php after a failed login attempt does not work as we are just redirected back to the login view.

Since a failed login results in a redirect to /login.php?failed=1, it is possible that the web server only cleans up the session variable when the failed parameter is set. So we could bypass authentication by attempting an invalid login, then dropping the redirect, and finally accessing the post-login page. To do so, we first attempt an invalid login for the admin user:

```http
HTTP POST request to /login.php on psp_authbypass.htb. Includes username admin and password asd. Response is 302 Found, sets session cookie, and redirects to login.php?failed=1.
```

We can then take note of the session cookie and use it to access the application as the admin user:

```http
HTTP GET request to /profile.php on psp_authbypass.htb with session cookie. Response shows status "logged in" with username "admin".
```

Again, make sure that it is clear why this vulnerability exists. The web server populates the session variable prematurely before the login process is complete to display the username in the warning. The session variable is only cleaned up after a redirect, which can be dropped by an attacker leading to an authentication bypass.

In simplified code, the vulnerability results like this. The login process sets the session variables that determine whether a user is authenticated or not before the result of the authentication is known, which is before the user's password is checked. The variables are only unset if the redirect to /login.php?failed=1 is sent:

```php
<SNIP>

if(isset($_POST['Submit'])){
	$_SESSION['Username'] = $_POST['Username'];
	$_SESSION['Active'] = true;

	// check user credentials
	if(login($Username, $_POST['Password'])) {
	    header("Location: profile.php");
	    exit;

	} else {
	    header("Location: login.php?failed=1");
        exit;
    }
}
if (isset($_GET['failed'])) {
	session_destroy();
    session_start();
}

<SNIP>
```

