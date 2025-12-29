# Bypassing Flawed Validation

If a web application uses the host header for any purpose, it is not uncommon for the application to implement certain checks to attempt to catch requests with manipulated host headers. In this section, we will have a look at a flawed validation function that leaves the web application vulnerable to host header attacks.

## Identification

Let's assume our target web application resides at `bypassingchecks.htb`. When we visit the domain, we can see a simple web application that tells us that it implements host header validation:

```http
http://<SERVER_IP>:<PORT>/
```
Simple Website page with navigation tabs for Home and Admin Area. Contains a Lorem Ipsum text section and a news update: "We have implemented host-header validation to protect us from hackers!".

Looking at the network traffic in Burp, we can see that the application uses absolute URLs to load resources such as stylesheets and script files:

```http
HTTP GET request to / on bypassingchecks.htb. Response includes HTML with title "Welcome", a stylesheet link to style.css, and a script source main.js.
```

However, when we attempt to send a request with an arbitrary host header, the application responds with an error message, indicating that some sort of host header validation is implemented:

```http
HTTP GET request to / on evil.htb. Response is 200 OK with message "Host Header attack detected!".
```

## Exploitation

To bypass the implemented filters, we need to think about how it might work and what kind of loopholes may exist. We can deduce from the behavior that the web application probably implements a filter that checks the supplied host header against a pre-configured domain stored in a configuration file. Supplying an arbitrary domain in the host header will thus be caught by the filter. However, there may be other ways to bypass it.

For instance, since web applications may run on a non-default port during testing, the validation function that parses the host header might omit the port. We could try this by specifying an arbitrary port in the host header:

```http
GET / HTTP/1.1
Host: bypassingchecks.htb:1337
```

The web application does not respond with an error message but accepts the supplied host header and constructs the absolute links with the incorrect port we provided. If we could combine this with a web cache poisoning attack, the result is a defacement attack, meaning the target website is defaced by malicious input. If we display the response in the browser, we can see that the website now looks completely different. That is because the link to the stylesheet is broken and does not load the stylesheet properly. This also affects the script file loaded with an absolute link, thus also potentially breaking the functionality of the target site:

```http
http://<SERVER_IP>:<PORT>/
```
Simple Website page with links to Home and Admin Area. Contains a Lorem Ipsum text section.

However, a defacement attack does not allow us to attack other users directly. Another common flaw in host header validation is that only the postfix of the domain is checked. This allows for subdomains to pass the host header validation as well. However, if the filter does not properly check if the host header indeed contains a subdomain of the target domain by checking for the separating dot, we might be able to supply a host header that contains the intended domain as a postfix. For instance, we can trick the filter by sending a request like this:

```http
GET / HTTP/1.1
Host: evilbypassingchecks.htb
```

We can register the domain `evilbypassingchecks.htb` which is entirely independent of the domain `bypassingchecks.htb` and then exploit the host header attack vectors discussed previously, such as web cache poisoning or password reset poisoning.

## Bypassing Blacklists

While the above example implements a (flawed) whitelist approach, some applications also implement a less secure blacklist approach. Blacklist implementations are generally easier to bypass since they only block what was explicitly thought of by the developers. Assume that a web application implements a blacklist filter for the host header that prevents access with a host header containing `localhost` or something equivalent. The most trivial blacklist may only contain `localhost` and `127.0.0.1`. However, there are many other values with the same meaning that an attacker could use to bypass this blacklist.

For instance, an attacker can supply the IP address in hexadecimal encoding: `0x7f000001`. We can verify that this is indeed equivalent to `localhost` by running the `ping` command:

```bash
ping 0x7f000001 -c 1
```
We can see that `0x7f000001` gets resolved to `localhost`. Following is a list of further options we could provide to bypass such a filter. We can again run a `ping` command with these values to confirm that they are equivalent to `localhost`:

*   Decimal encoding: `2130706433`
*   Hex encoding: `0x7f000001`
*   Octal encoding: `0177.0000.0000.0001`
*   Zero: `0`
*   Short form: `127.1`
*   IPv6: `::1`
*   IPv4 address in IPv6 format: `[0:0:0:0:0:ffff:127.0.0.1]` or `[::ffff:127.0.0.1]`
*   External domain that resolves to localhost: `localtest.me`

