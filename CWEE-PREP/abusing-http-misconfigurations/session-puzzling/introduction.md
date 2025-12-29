# Introduction to Session Puzzling

Sessions are important in HTTP to provide context for actions taken by the user. As such, sessions are a common target of attackers since stealing a user's active session allows an attacker to effectively take over the victim's account. Therefore, vulnerabilities regarding HTTP sessions often come with a particularly high impact. In this module, we will discuss common vulnerabilities that arise from improper usage of session variables by a web application.

## HTTP is a stateless protocol

HTTP is a stateless protocol. This is a fact that you've probably heard before. But what exactly does it mean? In the RFC7230 for HTTP/1.1 it says:

> HTTP is defined as a stateless protocol, meaning that each request message can be understood in isolation

More specifically, this means that a request must not be viewed in the context of another request, but on its own. Requests are independent of each other. In a practical example, this means that in an online shop, a request to add an item to your cart and the subsequent request to process the payment are completely separate. So how does the web application know how much you need to pay for the items in your cart? Session variables, session tokens, and session cookies are used to provide the necessary context to perform such related actions.

On the other hand, protocols such as TCP are stateful since it maintains a state. TCP includes a sequence number that is used to ensure packets are received in the correct order. Therefore, two TCP packets cannot be viewed in isolation but in context to each other. TCP thus maintains a state and is stateful.

## Stateful & Stateless Session Tokens

Session tokens used in HTTP are generally either stateful or stateless. The difference lies in the amount of data stored on the web server. In stateful authentication, the server generates a random session token that identifies the client's session. The server then stores data linking the session token to the user in memory. For instance, a stateful session token in a cookie may look like this:

```http
Set-Cookie: PHPSESSID=hvplcmsh88ja77r3dutanmn68u;
```

The server needs to store which user in the database this specific session token is linked to in order to be able to identify the user when presented with the session token. We can access the content of the session variables in PHP on the web server in the `/var/lib/php/sessions/` directory:

```bash
ls -la /var/lib/php/sessions/
```
```text
total 4
drwx-wx-wt 1 root     root     62 Jan 29 10:55 .
drwxr-xr-x 1 root     root     30 Jan 29 10:53 ..
-rw------- 1 www-data www-data 35 Jan 29 10:55 sess_hvplcmsh88ja77r3dutanmn68u
```

```bash
cat /var/lib/php/sessions/sess_hvplcmsh88ja77r3dutanmn68u
```
```text
Username|s:8:"testuser";Active|b:1;
```

In the above example, the session variables of our session ID contain a Username string set to `testuser`, and a boolean `Active` that indicates whether we are authenticated or not.

On the other hand, stateless session tokens contain all the necessary information in the token itself. The token is protected using a cryptographic signature such that malicious actors cannot just manipulate the data contained within the token to trick the web server. An example of stateless tokens are JSON Web Tokens (JWTs). JWTs consist of three parts:

*   General information about the JWT. This includes the signature algorithm.
*   The token body. This contains all information relating to the user's session.
*   The signature. This is the cryptographic signature protecting the token from manipulation.

A JWT in a cookie may look like this:

```http
Set-Cookie: auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Imh0Yi1zdGRudCIsImVtYWlsIjoiaHRiLXN0ZG50QGFjYWRlbXkuaHRiIiwidXNlcmlkIjo1fQ.SDV6L9UfR09hJ1C_hbRB1gWh-sjjqf_hYwOZG223Bkk
```

JWTs contain base64-encoded data. We can use a website like `jwt.io` to inspect the session token. When doing so, we can see that the above token contains the following user data:

```json
{
  "sub": "1234567890",
  "name": "htb-stdnt",
  "email": "htb-stdnt@academy.htb",
  "userid": 5
}
```

The Attacking Authentication Mechanisms module covers JWT's in more depth.

## Session Puzzling

Session puzzling is a vulnerability that results from improper handling of session variables. The impact and severity are highly dependent on the specific web application.

In PHP, stateful session tokens are used by default. After a session is created, the web server can store arbitrary data associated with the user's session in the `$_SESSION` array. Consider the following simplistic example:

```php
<?php
require_once ('db.php');
session_start();

// login
if(check_password($_POST['username'], $_POST['password'])) {
	$_SESSION['user_id'] = get_user_id($username);
    header("Location: profile.php");
    die();
} else {
	echo "Unauthorized";
}

// logout
if(isset($_POST['logout'])) {
	$_SESSION['user_id'] = 0;
}

?>
```

When we log in, the web server checks our username and password. If the login is successful, our user id is stored in the session variables. We are then redirected to the post-login page. Accessing the post-login page directly without a prior login will likely not work, as the web server checks for a valid `user_id` in the session variables. Since there is no way for us to manipulate the session variables, we can thus only access the post-login page if we successfully logged in previously.

However, this code still contains an issue. When logging out, the session is not destroyed but rather the `user_id` is set to zero. This can be a problem if zero is a valid user ID, for instance for the admin user. In that case, an attacker could log into his own account, log out, and then access `/profile.php` to find that he is logged in as the admin user:

```http
http://<SERVER_IP>:<PORT>/
```
Status page showing "logged in" with username "admin" and description "Secret Admin Information".

This would be a simple session puzzling vulnerability due to unsafe default values, as the default value for the `user_id` parameter is the user id of the admin user and thus not safe.

