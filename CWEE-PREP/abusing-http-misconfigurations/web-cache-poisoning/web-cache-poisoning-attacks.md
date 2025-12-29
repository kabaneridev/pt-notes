# Web Cache Poisoning Attacks

Web cache poisoning is typically used to distribute an underlying vulnerability in the web application to a large number of users. This makes the exploitation of web cache poisoning highly dependent on the specific web application. Additionally, poisoning the cache is often not trivial. In real-world scenarios, many users access the web application concurrently. Therefore, when you request a page, it is most likely already cached, and you are only served the cached response. In these cases, you need to send your malicious request at the exact time that the cache expires to get the web cache to store the response. Getting this timing right involves a lot of trial and error. However, it can be significantly easier if the web server reveals information about the expiry of the cache.

## Exploitation & Impact of Web Cache Poisoning

### XSS

The exploitation of web cache poisoning depends on the underlying issue in the web application itself. In the previous section, we saw an example of how web cache poisoning using an unkeyed GET parameter can distribute reflected XSS vulnerabilities to unknowing users, eliminating the need for user interaction. Furthermore, we demonstrated that an XSS vulnerability via an unkeyed HTTP header, which was unexploitable on its own, can be weaponized with the help of web cache poisoning. XSS is one of the most common ways of exploiting web cache poisoning, though other methods exist.

### Unkeyed Cookies

Another example is the exploitation of unkeyed cookies. If a web application utilizes a user cookie to remember certain user choices, and this cookie is unkeyed, it can be used to poison the cache and force these choices upon other users. For instance, assume the cookie `consent` is used to remember if the user consented to something being displayed on the page. If this cookie is unkeyed, an attacker could send the following request:

```http
GET /index.php HTTP/1.1
Host: webcache.htb
Cookie: consent=1;
```

If the response is cached, all users who visit the website will be served the content as if they already consented. Similar attacks are possible if the web application uses unkeyed cookies to determine the layout of the application (e.g., in a `color=blue` cookie) or the language of the application (e.g., in a `language=en` cookie). While these types of cache poisoning vulnerabilities do occur, they are often detected by website maintainers relatively quickly because the cache is poisoned during normal interaction with the website. For instance, if a user sets the layout to blue via the `color=blue` cookie and the response is cached, all subsequent requests made by other users who have chosen a different color will still be served the blue layout, making it quite obvious that something is not working correctly.

### Denial-of-Service

Another type of web cache poisoning vulnerability revolves around the Host header. We will delve into Host header attacks in more detail in an upcoming section, so we will not discuss it exhaustively here. However, consider a scenario where a faulty web cache includes the Host header in its cache key but applies normalization before caching by stripping the port. The underlying web application then uses the Host header to construct an absolute URL for a redirect. A request similar to this:

```http
GET / HTTP/1.1
Host: webcache.htb:80
```

would result in a response like this:

```http
HTTP/1.1 302 Found
Location: http://webcache.htb:80/index.php
```

While the port is present in the response, it is not considered part of the cache key due to the flawed behavior of the web cache. This means we could achieve a Denial-of-Service (DoS) by sending a request like this:

```http
GET / HTTP/1.1
Host: webcache.htb:1337
```

If the response is cached, all users who try to access the site will be redirected to port 1337. Since the web application runs on port 80, users will be unable to access the site, resulting in a DoS.

### Remarks

One of the most challenging aspects of web cache poisoning is ensuring that a response is cached. When many users access a website, it is unlikely that the cache is empty when you send your malicious payload, meaning you will likely be served an already cached response, and your request may never hit the web server.

You can try to bypass the web cache by setting the `Cache-Control: no-cache` header in your request. Most caches will respect this header in the default configuration and will check with the web server before serving you the response. This allows you to force your request to hit the web server even if a cached entry with the same cache key exists. If this does not work, you could also try the deprecated `Pragma: no-cache` header.

However, these headers cannot be used to force the web cache to refresh the stored copy. To force your poisoned response to be cached, you need to wait until the current cache expires and then time your request correctly for it to be cached. This involves a lot of guesswork. In some cases, the server informs you about how long a cached resource is considered fresh. You can look for the `Cache-Control` header in the response to check how many seconds the response remains fresh.

### Impact

The impact of web cache poisoning is difficult to generalize. It heavily depends on the vulnerability that can be distributed, how reliably the attacker can poison the cache, how long the payload is cached for, and how many potential victims access the page within that timeframe.

The impact can also vary based on the cache configuration. If certain HTTP headers, such as the `User-Agent`, are included in the cache key, an attacker needs to poison the cache for each target group separately, as the web cache will serve different cached responses for different `User-Agent` headers.

## Cache Busters

In real-world scenarios, it's crucial to ensure that your poisoned response is not served to any legitimate users of the web application. You can achieve this by adding a **cache buster** to all of your requests. A cache buster is a unique parameter value that only you use to guarantee a unique cache key. Since you have a unique cache key, only you receive the poisoned response, and no real users are affected.

For example, let's revisit the web application from the previous section. If you know that an admin user is German and visits the website using the `language=de` parameter, to ensure they do not receive a poisoned response until your payload is complete, you should use a cache buster in the `language` parameter. For instance, when you determined that the `ref` parameter is unkeyed and built a proof of concept for XSS, you might have used a request like:

```http
GET /index.php?language=unusedvalue&ref="><script>alert(1)</script> HTTP/1.1
Host: webcache.htb
```

Since the value "unusedvalue" sent in the `language` parameter is unique and would likely never be set by a real user, it acts as your cache buster. Keep in mind that you must use a different cache buster in follow-up requests, as the cache key with `language=unusedvalue` already exists from your previous request. Therefore, you would need to slightly adjust the value of the `language` parameter to generate a new, unique, and unused cache key.

