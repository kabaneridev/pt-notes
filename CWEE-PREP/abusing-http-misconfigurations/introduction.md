# Introduction to HTTP Misconfigurations

HTTP, being one of the most widely utilized protocols on the Internet, underpins billions of devices daily. Web application security is a vital component of Cybersecurity, requiring a holistic view of web applications within their real-world deployments, which often include systems like web servers and web caches that introduce additional complexity and attack surface.

This module will cover three common HTTP attacks prevalent in modern web applications. We will discuss these attacks in detail, including detection, exploitation, and prevention methods.

Web services that cater to numerous users often employ web caches to enhance performance by reducing the load on the web server. Web caches operate between the client and the web server, storing resources locally after retrieving them from the origin server. This allows them to serve these resources from local storage if the same resource is requested again, thereby reducing the load on the web server. Vulnerabilities that can arise from the use of web caches will be explored in this module.

The HTTP Host header, present in every HTTP/1.1 request and later, specifies the hostname and optionally the port of the server to which the request is being sent. When web servers host multiple web applications, the Host header is used to determine which web application is targeted by the request, and the appropriate response is served. This module will discuss vulnerabilities that can stem from improper handling of the Host header within web applications.

Since HTTP is a stateless protocol, sessions are essential for providing context to requests. For example, HTTP sessions are used to perform authenticated actions without needing to send credentials with every request. Typically, the web application identifies the user by their session ID, which is usually provided by the user in a session cookie. On the server side, information about the user is stored in session variables associated with the corresponding session ID. The final part of this module focuses on vulnerabilities that result from improper handling of session variables.

## HTTP Attacks

### Web Cache Poisoning

The first HTTP attack discussed in this module is Web Cache Poisoning. This attack exploits misconfigurations in web caches, often in conjunction with other vulnerabilities in the underlying web application, to target unsuspecting users. Depending on the specific vulnerability, merely accessing the targeted website might be sufficient for a victim to be exploited. Web cache poisoning can also weaponize otherwise unexploitable vulnerabilities to target a large number of potential victims.

### Host Header Attacks

The second type of attacks discussed in this module are Host Header Attacks. The HTTP Host header contains the host of the accessed domain and is used to inform the server which domain a user wishes to access. This is necessary for scenarios where a single server hosts multiple domains or subdomains, allowing the server to identify the intended application. Host header attacks exploit vulnerabilities in the handling of the Host header. More specifically, if a web application uses the Host header for authorization checks or to construct absolute links, an attacker may be able to manipulate the Host header to bypass these checks or force the creation of malicious links.

### Session Puzzling

The third and final attack covered in this module is Session Puzzling. As HTTP is a stateless protocol, session variables are necessary to track a wide range of actions commonly performed in web applications, including authentication. Session puzzling is a vulnerability that results from improper handling of session variables and can lead to authentication bypasses or account takeover. In particular, session puzzling can arise from the reuse of the same session variable across different processes, the premature population of session variables, or insecure default values for session variables.

Let's begin by discussing the first of these attacks in the next section.

