# Introduction to HTTP Attacks

In real-world deployment contexts of web applications, we often face additional complexity due to intermediary systems such as reverse proxies. Similarly to the Abusing HTTP Misconfigurations module, we will cover three HTTP attacks that are common in modern web applications, discussing how to detect, exploit, and prevent them, in addition to knowing the misconfigurations that cause them. Prior completion of the Abusing HTTP Misconfiguration module is not required since we cover three different HTTP vulnerabilities here.

Since HTTP is a stateless protocol, we often view HTTP requests isolated from each other. However, HTTP/1.1 allows the reuse of TCP sockets to send multiple requests and responses to improve performance. In that case, the TCP stream contains multiple HTTP requests. To determine where one request ends and the next one begins, the web server needs to know the length of each request's body. To determine the length, the `Content-Length` or `Transfer-Encoding` HTTP headers can be used. While the `Content-Length` header specifies the length of the request body in bytes, the `Transfer-Encoding` header can specify a chunked encoding which indicates that the request body contains multiple chunks of data. In this module, we will discuss vulnerabilities that arise from inconsistencies and discrepancies between multiple systems in determining the length of HTTP requests.

HTTP/2 implements many improvements over HTTP/1.1. While HTTP/1.1 is a string-based protocol, HTTP/2 is a binary protocol, meaning requests and responses are transmitted in a binary format to improve performance. Additionally, HTTP/2 uses a built-in mechanism to specify the length of the request's body. In some deployment settings, HTTP/2 requests are rewritten to HTTP/1.1 by an intermediary system before forwarding the request to the web server. We will discuss vulnerabilities that can be caused by such deployment settings.

## HTTP Attacks

### CRLF Injection

The first HTTP attack discussed in this module is CRLF Injection. This attack exploits improper validation of user input. The term CRLF consists of the name of the two control characters Carriage Return (CR) and Line Feed (LF) that mark the beginning of a new line. As such, CRLF injection attacks arise when a web application does not sanitize the CRLF control characters in user input. The impact differs depending on the underlying web application and can be a minor issue or a major security flaw.

### HTTP Request Smuggling/Desync Attacks

The second attack discussed in this module is HTTP Request Smuggling, sometimes also called Desync Attacks as they create desynchronization between the reverse proxy and the web server behind it. This is an advanced attack that allows an attacker to bypass security controls such as Web Application Firewalls (WAFs) or completely compromise other users by influencing their requests.

### HTTP/2 Downgrade Attack

The third and final attack covered in this module is a HTTP/2 Downgrade Attack or HTTP/2 Request Smuggling. HTTP/2 implements measures that effectively prevent request smuggling attacks entirely. However, since HTTP/2 is not widely supported yet, there are deployment settings where the user talks HTTP/2 to the reverse proxy, but the reverse proxy talks HTTP/1.1 to the actual web server. These settings may be vulnerable to request smuggling even though HTTP/2 is used in the front end.

Let's get started by discussing the first of these attacks in the next section.


