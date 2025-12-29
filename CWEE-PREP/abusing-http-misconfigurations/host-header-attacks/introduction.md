# Introduction to Host Header Attacks

## HTTP Host Header

The `Host` header is a mandatory header since HTTP/1.1 and specifies the host targeted by an HTTP request. This is particularly important in a scenario where a web server runs multiple different web applications and needs to distinguish between them. Depending on the value of the host header in a request, the web server serves a different response. This is independent of DNS and allows multiple web applications to be run on the same IP address and port (which is either port 80 or 443 by default for web applications). Since this is common practice, requests without a valid `Host` header potentially lead to routing issues.

Content Delivery Networks (CDNs) such as Akamai or Cloudflare also rely on the host header to determine which web application to serve. While CDNs typically host different web applications on separate machines, CDN traffic is by its nature routed over intermediary systems such as reverse proxies, web caches, and load balancers. These intermediary systems need to know where to forward the traffic which they decide based on the host header in the request.

To demonstrate this further, let's have a look at the following simple Apache configuration for a web server with two different virtual hosts:

```bash
<VirtualHost *:80>
    DocumentRoot "/var/www/testapp"
    ServerName testapp.htb
</VirtualHost>

<VirtualHost *:80>
    DocumentRoot "/var/www/anotherdomain"
    ServerName anotherdomain.org
</VirtualHost>
```

We can see that there are two entirely different web applications located on different paths on the local system. The difference is the `ServerName` directive, which tells Apache to serve the corresponding web application depending on the host header of the incoming request. For instance, we get routed to the first web application if the host header is `testapp.htb`:

```http
HTTP GET request to / on testapp.htb. Response is 200 OK with server details and content "Hello World!".
```

However, we get served an entirely different response if the host header is `anotherdomain.org`:

```http
HTTP GET request to / on anotherdomain.org. Response is 200 OK with server details and content "This is an entirely different domain".
```

For more details on vhosts and vhost brute forcing, check out the Attacking Web Applications with Ffuf module here.

## Host Header Vulnerabilities

Host header vulnerabilities are the result of improper or unsafe handling of the host header by the web application. Vulnerable web applications trust the host header without proper validation or sanitization which can lead to different vulnerabilities. For instance, since the host header is user-controllable, it should not be used for authentication checks. Improper handling of the host header can thus lead to authentication bypasses.

Web applications need to know the domain they are hosted on to generate absolute links, which are required in different situations such as password reset links. If the domain is not stored in a configuration file and the web application uses the host header for generating absolute links without proper checks, it might be vulnerable to a vulnerability called password reset poisoning.

In a real-world setting where a web application is hosted on the publicly accessible internet, host header vulnerabilities might be difficult to test for and detect, since it can be impossible to send requests with arbitrary host headers to the target. That is because of intermediate systems such as CDNs, which route the request based on the host header. Therefore, if the host header contains an invalid value, the intermediary system might not know where to route the traffic and just drop the request or respond with an error. However, in these scenarios, host header attacks might still be exploitable in combination with other attack vectors such as web cache poisoning.

## Override Headers

When discussing host header attacks, it is important to keep in mind that there are other headers with a similar meaning to the host header that web servers might (perhaps unknowingly to the administrator) support and can thus be exploited for host header attacks. These headers are called Override Headers since they override the meaning of the original host header. Override headers include:

*   `X-Forwarded-Host`
*   `X-HTTP-Host-Override`
*   `Forwarded`
*   `X-Host`
*   `X-Forwarded-Server`

Perhaps there are scenarios where validation is in place but only applied to the host header and not to override headers, but the web application supports override headers if they are set. This could lead to validation bypasses and enable host header attacks.

