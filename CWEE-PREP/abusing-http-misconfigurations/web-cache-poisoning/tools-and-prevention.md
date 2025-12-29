# Tools & Prevention

After discussing different ways to identify and exploit web cache poisoning vulnerabilities, let's look at tools we can use to help us in this process. Afterward, we will discuss ways we can protect ourselves from web cache poisoning vulnerabilities.

## Tools of the Trade

One of the most important tasks when searching for web cache poisoning vulnerabilities is identifying which parameters of a request are keyed and which are unkeyed. We can use the Web-Cache-Vulnerability-Scanner (WCVS) to help us identify web cache poisoning vulnerabilities. The tool can be downloaded from its GitHub release page. Afterward, we need to unpack it and run the binary:

```bash
tar xzf web-cache-vulnerability-scanner_1.1.0_linux_amd64.tar.gz
./wcvs -h
```

WCVS comes with a header and parameter wordlist which it uses to find parameters that are keyed/unkeyed. The tool also automatically adds a cache buster to each request, so we don't have to worry about accidentally poisoning other users' responses. We can run a simple scan of a web application by specifying the URL in the `-u` parameter. Since the web application redirects us and sets the GET parameter `language=en`, we also have to specify this GET parameter with the `-sp` flag. Lastly, we can tell WCVS to generate a report with the `-gr` flag:

```bash
./wcvs -u http://simple.wcp.htb/ -sp language=en -gr
```

WCVS can identify web cache poisoning with the query parameter `ref`. If we look in the JSON report that WCVS generated, we can see the proof of concept request:

```json
{
    "technique": "Parameters",
    "hasError": false,
    "errorMessages": null,
    "isVulnerable": true,
    "requests": [
        {
            "reason": "Response Body contained 793369015723",
            "request": "GET /?language=en&ref=793369015723&cb=829054467467 HTTP/1.1\r\nHost: simple.wcp.htb\r\nUser-Agent: WebCacheVulnerabilityScanner v1.1.0\r\nAccept-Encoding: gzip\r\n\r\n",
            "response": ""
        }
    ]
}
```

The tool can also help us identify more advanced web cache poisoning vulnerabilities that require the exploitation of fat GET requests or parameter cloaking:

```bash
./wcvs -u http://fatget.wcp.htb/ -sp language=en -gr
```

This scan will identify web cache poisoning vulnerabilities via HTTP headers and fat GET cache poisoning. The tool can be installed using `go`:

```bash
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner/v2@latest
./go/bin/Web-Cache-Vulnerability-Scanner -u http://STMIP:STMPO/ -sp language=en -gr
```

## Web Cache Poisoning Prevention

Due to their complex nature, preventing web cache poisoning vulnerabilities is no easy task. In some settings, the backend developers might be unaware that there is a web cache in front of the web server in the actual deployment setting. Furthermore, the administrators configuring the web cache and the cache key might be different people than the backend developers. This can introduce hidden unkeyed parameters that the web application uses to alter the response, leading to potential web cache poisoning vectors.

Configuring the web cache properly depends highly on the web server and web application it is combined with. Thus, we need to ensure the following things:

*   Do not use the default web cache configuration. Configure the web cache properly according to your web application's needs.
*   Ensure that the web server does not support fat GET requests.
*   Ensure that every request parameter that influences the response in any way is keyed.
*   Keep the web cache and web server up to date to prevent bugs and other vulnerabilities which can potentially result in discrepancies in request parsing leading to parameter cloaking.
*   Ensure that all client-side vulnerabilities such as XSS are patched even if they are not exploitable in a classical sense (for instance via reflected XSS). This may be the case if a custom header is required. Web cache poisoning can make these vulnerabilities exploitable, so it is important to patch them.

Furthermore, administrators should assess if caching is required. Of course, web caches are important for many circumstances, however, there might be others where it is not required and only increases deployment complexity. Another less drastic approach might be limiting caching to only static resources such as stylesheets and scripts. This eliminates web cache poisoning entirely. Though it can create new issues if an attacker can trick the web cache into caching a resource that is not actually static.

