# Advanced Cache Poisoning Techniques

In the previous sections, we discussed basic techniques for identifying and exploiting web cache poisoning vulnerabilities. In this section, we will delve into two advanced web cache poisoning techniques that exploit misconfigurations in the web server to make otherwise secure configurations vulnerable.

## Fat GET

Fat GET requests are HTTP GET requests that contain a request body. While GET parameters are typically sent as part of the query string, any HTTP request can, by specification, contain a request body, regardless of the method. In the case of a GET request, the message body has no defined semantics, which is why it is rarely used. This is confirmed in RFC 7231, section 4.3.1:

> A payload within a GET request message has no defined semantics;
> sending a payload body on a GET request might cause some existing implementations to reject the request.

Therefore, a request body is explicitly allowed, but it should not have any effect. Thus, the following two GET requests are semantically equivalent, as the body should be disregarded in the second:

```http
GET /index.php?param1=Hello&param2=World HTTP/1.1
Host: fatget.wcp.htb
```

and

```http
GET /index.php?param1=Hello&param2=World HTTP/1.1
Host: fatget.wcp.htb
Content-Length: 10

param3=123
```

However, if the web server is misconfigured or implemented incorrectly, it may parse parameters from the request body of GET requests. This can lead to web cache poisoning attack vectors that would otherwise be unexploitable.

Let's consider an example web application, the same one from the previous section, but this time the `ref` GET parameter is keyed, preventing the previous web cache poisoning attack. To investigate if the web server supports fat GET requests, send a request similar to the following:

```http
GET /index.php?language=en HTTP/1.1
Host: fatget.wcp.htb
Content-Length: 11

language=de
```

The `language` GET parameter is set to English, so you would expect the page to display English text. However, upon inspection, the response contains German text. This indicates that the web server supports fat GET requests and even prioritizes parameters sent in the request body over actual GET parameters. Now, to confirm if this creates a discrepancy between the web cache and the web server, send the following request:

```http
GET /index.php?language=en HTTP/1.1
Host: fatget.wcp.htb
```

You should now get a cache hit, and the web cache returns the German page even though you set the `language` parameter to English. This means your first request poisoned the cache with your injected fat GET parameter, but the web cache correctly uses the GET parameter in the URL to determine the cache key. This flaw in the web server can be exploited for web cache poisoning.

After confirming that a reflected XSS vulnerability in the `ref` parameter is still present, you can use web cache poisoning to escalate this into a stored XSS vulnerability that forces an admin user to reveal sensitive information, similar to the previous section. Since the `ref` parameter is now keyed, you need to set it in a fat GET request with the following:

```http
GET /index.php?language=de HTTP/1.1
Host: fatget.wcp.htb
Content-Length: 142

ref="><script>var xhr = new XMLHttpRequest();xhr.open('GET', '/admin.php?reveal_flag=1', true);xhr.withCredentials = true;xhr.send();</script>
```

This should poison the cache. You can confirm this by sending a follow-up request. You should get a cache hit, and the response should contain your poisoned payload.

After waiting for a while, the admin user should access the page, execute your injected XSS payload, and reveal the sensitive information.

**Note:** Fat GET requests are typically a misconfiguration in the web server software, not in the web application itself.

## Parameter Cloaking

Another type of misconfiguration that can lead to a setup being vulnerable to web cache poisoning is parameter cloaking. Similar to fat GET requests, the goal is to create a discrepancy between the web server and the web cache such that the web cache uses a different parameter for the cache key than the web server uses to serve the response. The underlying idea is the same as with fat GET requests.

To exploit parameter cloaking, the web cache needs to parse parameters differently than the web server. Let's look at a real-world vulnerability in the Python web framework Bottle, disclosed under CVE-2020-28473. Bottle allows a semicolon for separation between different URL parameters. For example, a GET request to `/test?a=1;b=2`. Bottle treats the semicolon as a separation character, recognizing two GET parameters: `a` with a value of `1` and `b` with a value of `2`. The web cache, on the other hand, might only see one GET parameter, `a` with a value of `1;b=2`. Let's examine how to exploit this to achieve web cache poisoning.

When starting the web application, assume it's the same web application exploited with fat GET requests but ported to Python Bottle. Based on previous knowledge, the `language`, `content`, and `ref` parameters are keyed, and the reflected XSS vulnerabilities in `content` and `ref` are still present.

Now, to create a discrepancy between the web cache and web server by exploiting the vulnerability, you need an unkeyed parameter. Assume the parameter `a` is unkeyed. You can create a proof of concept with the following request:

```http
GET /?language=en&a=b;language=de HTTP/1.1
Host: cloak.wcp.htb
```

The response displays German text, even though the request contains `language=en`. This happens because Bottle prefers the last occurrence of each parameter, so `de` overrides `en` for the `language` parameter. Thus, Bottle serves the response containing German text. Since parameter `a` is unkeyed, the web cache stores this response for the cache key `language=en`. You can send the following follow-up request to confirm that the cache was poisoned:

```http
GET /?language=en HTTP/1.1
Host: cloak.wcp.htb
```

The response should now be a cache hit and contain the German text, confirming successful cache poisoning.

**Note:** To poison the cache with parameter cloaking, you need to "hide" the cloaked parameter from the cache key by appending it to an unkeyed parameter.

Now, let's build an XSS exploit that forces the admin user to reveal sensitive information. Since Bottle treats the semicolon as a separation character, you need to URL-encode all occurrences of the semicolon in your payload:

```http
GET /?language=de&a=b;ref=%22%3E%3Cscript%3Evar%20xhr%20=%20new%20XMLHttpRequest()%3bxhr.open(%27GET%27,%20%27/admin?reveal_flag=1%27,%20true)%3bxhr.withCredentials%20=%20true%3bxhr.send()%3b%3C/script%3E HTTP/1.1
Host: cloak.wcp.htb
```

After sending this request and confirming your payload has been cached for the URL `/?language=de`, the admin should trigger your exploit, and the sensitive information should be revealed after a few seconds.

