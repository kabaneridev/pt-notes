# Password Reset Poisoning

The first step of exploiting host header attacks is to determine if and how a web application uses the host header. To do that, we can manipulate the host header in a request and check for changes in the response. Do changes in the host header influence the response? If yes, how? Is there a way to exploit these changes by manipulating the host header in a certain way? If a web application uses absolute links anywhere, you should test for host header vulnerabilities.

Password reset poisoning is a fairly common vulnerability that is the result of improper use of the host header to construct password reset links.

## Identification

After starting the exercise, we see a simple web application that greets us with a login screen. After logging in with the provided credentials, the page displays some basic user information:

```http
http://<SERVER_IP>:<PORT>/profile.php
```
Web page showing status "logged in" with email htb-stdnt@httpattacks.htb. Description: "This is the user for HackTheBox Academy students." Navigation includes Home, About, Contact, and Log out.

There does not seem to be anything interesting here, so let's move on. When investigating the network traffic, we can see that the web application uses absolute links to load stylesheets and script files. We can test for a potential host header injection by sending a request with a manipulated host header and check whether the web application uses this manipulated host header to construct absolute links:

```http
HTTP GET request to /login.php on evil.htb. Response includes HTML with links to stylesheets: bootstrap.min.css and signin.css.
```

In the above screenshot, we can see that a manipulated host header with the value `evil.htb` results in the website reflecting the value in the URLs for the stylesheets. This is because the web application uses the host header to determine the domain for absolute links. This by itself is not an exploitable vulnerability though. We cannot send special characters in the host header to escalate this to an XSS because the web server rejects requests with such invalid host headers. Besides, without an additional vulnerability such as web cache poisoning, we cannot force a victim's browser to send a request with a manipulated host header. Therefore, a reflected XSS via the host header by itself is not exploitable.

Let's investigate the password reset functionality. When we reset our password, we get the following message:

```http
http://<SERVER_IP>:<PORT>/reset.php
```
Email input form with "Submit" button. Message displayed: "Success! Details have been sent via e-mail."

So the web application most likely sends a password reset link via email. In this lab we do not have access to an email account, however, a quick look behind the scenes reveals that the web application does indeed send an email looking like this:

```text
Email with subject "Password Reset" to htb-stdnt@httpattacks.htb. Contains a link to reset password: http://127.0.0.1:8000/pw_reset.php?token=....
```

So we successfully identified that the web application uses the host header to construct absolute links. Additionally, we know that the application sends password reset links with a password reset token via email. How could we exploit this?

## Exploitation

To successfully exploit password reset poisoning, we need to send a password reset request with the email of the victim and a manipulated host header that points to a domain under our control. The web application uses the manipulated host header to construct the password reset link such that the link points to our domain. When the victim now clicks the password reset link, we will be able to see the request on our domain. Most importantly, the request contains the victim's password reset token in the URL. This allows us to steal the reset token, reset the victim's password, and then take over their account.

Let's execute a password reset poisoning attack against the admin user with the email address `admin@httpattacks.htb` on our vulnerable web application. To exfiltrate the data, we can use a tool like Interactsh. In particular, we can use the browser version which is available here: `https://app.interactsh.com/`. After a couple of seconds, we obtain a domain name that we can then use in the host header in the password reset request for the admin user:

```http
HTTP POST request to /reset.php on cfatjbh2vtc0000rfn0gg8ipj8ryyyybb.oast.fun. Includes username admin@httpattacks.htb. Response is 200 OK with server details and cache control headers.
```

The web application sends a password reset link to the admin user using an absolute link that it constructed from the manipulated host header we provided. When the admin user clicks the link, we can see the request on the Interactsh website:

```http
HTTP GET request to /pw_reset.php with token on cezg3yf2vtc00000dhy0g8xab9cyyyyyb.oast.fun. Connection set to close, content type is application/x-www-form-urlencoded.
```

We can now use the admin user's password reset token to reset the password and log in with the admin account.

Password reset poisoning is a vulnerability that requires user interaction, as the victim needs to click the poisoned link to enable the attacker to steal the password reset token. Most web applications use HTML to format emails and particularly links. This obfuscates the domain name of the link, such that victims might not notice that the domain name is poisoned until after they have already clicked the link. However, at that point, it is too late as the attacker has already obtained the password reset token.

### Solving the lab

Due to technical limitations, the lab does not have access to the public internet, thus we cannot use `https://app.interactsh.com/` to exfiltrate data since it cannot be reached from the lab instance. Instead, the lab contains a custom implementation on the virtual host `interactsh.local`. All requests to `interactsh.local` are logged, just like `https://app.interactsh.com/` logs all requests to the generated subdomain. To retrieve the logged requests, we have to access the URL `/log` on the virtual host `interactsh.local`.

When visiting the `/login.php` webpage of the spawned target machine web application and clicking on `Forgot Password?`, you need to use the email address of the admin `admin@httpattacks.htb` and intercept the request with Burp Suite. When keeping the default Host header and assigning it the value `interactsh.local`, you will notice that there are no password reset tokens received from the admin in `http://interactsh.local:STMPO/log`. Therefore, you need to use the Override Header `X-Forwarded-Host`, specifying `interactsh.local` as its value. Subsequently, when checking the logs over `http://interactsh.local:STMPO/log`, you will find that the admin has requested a password reset with a token. Therefore, you need to copy the entire path (i.e., `/pw_reset.php?token=...`) and visit it to change the password of the admin. It is always a good practice to use cryptographically secure passwords to prevent other threat agents from gaining access. You can use `openssl` for this:

```bash
openssl rand -hex 16
```

