# Common Session Variables (Auth Bypass)

In our first instance of session puzzling, we will have a look at a basic scenario in which a session variable is re-used in multiple places. Successfully identifying session puzzling vulnerabilities can be challenging. The process of looking for these types of vulnerabilities is similar to the process of looking for business logic vulnerabilities. We have to identify places where session variables are used and think of what might go wrong on the web server. Let's have a look at a basic example of common session variables that lead to an authentication bypass.

## Identification

### Overview of the Web Application

The exercise below is a simple web application that provides login functionality. After logging in with the provided credentials, the application displays basic user information:

```http
http://<SERVER_IP>:<PORT>/profile.php
```
Status page showing "logged in" with username "htb-stdnt". Description: "This is the user for HackTheBox Academy students." Navigation includes Home, About, Contact, and Log out.

When logging back out, we can see that the application also provides a Forgot password functionality. After providing our username, we have to answer a security question:

```http
http://<SERVER_IP>:<PORT>/reset_2.php
```
Question prompt asking "What is 2+2?" with an answer input field and a "Submit" button.

After answering the question correctly, we are allowed to set a new password for the account. Let's try to access another user's account by resetting their password. When trying to set the username `admin`, we can see the admin user's security question:

```http
http://<SERVER_IP>:<PORT>/reset_2.php
```
Security question asking What is your first pet's name? with an answer input field and a Submit button.'
Unfortunately, we do not know the answer to that question. So instead, let's analyze the network traffic to see if we can identify a session puzzling vulnerability.

### Analyzing Session Variables

When analyzing the network traffic generated during a password reset flow, we can see that there are multiple steps:

*   In the first step, we provide the user name.
*   In the second step, we provide the answer to the security question.
*   In the third step, we provide the new password.

Since these steps are handled in subsequent HTTP requests, and the answer to the previous steps is not contained in the follow-up requests, we can deduce that session variables are used to store user information. More specifically, when we supply the response to the security question, our request does not contain the username. However, the backend somehow has to know our user information to check whether our response was correct. Therefore, it is likely that user information was stored in the session variables:

```http
HTTP POST request to /reset_2.php on csv_authbypass.htb. Includes answer 4 and session cookie. Response is 302 Found, redirects to reset_3.php.
```

We can verify this by sending the same request again without the session cookie. We are now getting redirected back to the login page and a new session is created:

```http
HTTP POST request to /reset_2.php on csv_authbypass.htb. Includes answer 4. Response is 302 Found, sets session cookie, and redirects to login.php.
```

So after analyzing the traffic, we now know that session variables are used in the multi-part password reset flow to store information about the user. The next question is: how do we identify and exploit a vulnerability?

## Exploitation

In the previous subsection, we identified that the first step of the password reset process makes the backend store user information in session variables. How could we exploit that?

The first approach could be to attempt to bypass the security question altogether. We can first send the username `admin` to the endpoint `/reset_1.php`, which would make the web server store the admin user in the session variables. If there is no additional check, we could maybe access the password reset endpoint `/reset_3.php` directly, skipping the security question. Let's try this by first setting our username to admin with the following request:

```http
HTTP POST request to /reset_1.php on csv_authbypass.htb. Includes username admin. Response is 302 Found, sets session cookie, and redirects to reset_2.php.
```

We can see that we get a fresh session cookie and are redirected to the second step. Let's now use that session to attempt a password reset directly at `/reset_3.php` thereby skipping the security question:

```http
HTTP POST request to /reset_3.php on csv_authbypass.htb. Includes password P@ssw0rd!. Response is 302 Found, redirects to login.php with message "Please complete Phase 2 first".
```

The web server tells us that we need to complete phase 2 (which is the security question) first and redirects us back to the login page. So that apparently did not work.

Another potential vulnerability would be the re-use of the same session variable for the password reset process and the authentication process. If successful authentication stores the logged-in user in the same session variable that the web server uses to store the user in the password reset process, we might be able to bypass authentication entirely.

To test for that, click on `Forgot Password?` and enter the username `admin`. Afterward, access the post-login endpoint at `/profile.php` directly. We are now logged in as the admin user by exploiting our first session puzzling vulnerability.

Make sure that you understand why this vulnerability exists on the backend. The web server checks whether a user is logged in by checking whether the session variables contain a valid username. However, the same session variable is used in the password reset process, such that we can set the username with the password reset functionality and then bypass the authentication check.

In simplified code, the vulnerability results like this. The first phase of the password reset process in `reset_1.php` sets the session variable `Username` to the username provided by the user:

```php
<SNIP>

if(isset($_POST['Submit'])){
	$_SESSION['Username'] = $_POST['Username'];
	header("Location: reset_2.php");
	exit;
}

<SNIP>
```

The authentication process utilizes the same session variable and authentication in `profile.php` only checks if this session variable is set:

```php
<SNIP>

if(!isset($_SESSION['Username'])){
    header("Location: login.php");
	exit;
  }

<SNIP>
```

