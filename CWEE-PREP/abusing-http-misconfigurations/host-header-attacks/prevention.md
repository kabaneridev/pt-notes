# Host Header Attacks Prevention

After discussing different ways to identify and exploit host header vulnerabilities, let's see how we can protect ourselves from these types of attacks. Improper handling of the host header combined with missing or flawed validation is typically the source of host header attacks. In this section, we will look at samples of vulnerable code and configurations and discuss how we can patch them.

## Insecure Configurations

### Blind Trust in the Host Header

The simplest and most obvious host header attacks arise from web applications that blindly trust the host header. This is quite rare in the real world but can happen if the developer is unaware that the host header can be arbitrarily changed by the user. Let's have a look at the following code snippet:

```php
$headers = getallheaders();
$host_header = $headers['Host'];

if (is_local_request($host_header)) {
    echo "Welcome Admin!";
} else {
    echo "Unauthorized! The admin area can only be accessed locally!";
    die();
}
```

If the function `is_local_request` only checks if the host header is in a list of trusted values, this code is obviously vulnerable since an attacker can just brute-force or deduce a trusted value and bypass the authentication as discussed a few sections ago. Generally, authentication checks should never rely on the host header. If the source of a request is needed, the remote IP address should be considered. This can be done by accessing `$_SERVER['REMOTE_ADDR']` in PHP. However, an authentication process should generally rely on a secure authentication mechanism such as password authentication with a secure password. Additionally, if a web application should only be accessible from a local network, external access needs to be restricted using firewall rules.

In particular, internal web applications should not be run on the same web server as external web applications since this would allow access to the internal web applications via virtual host brute-forcing.

### Improper Host Header Validation

In general, a web application should avoid using the host header for altering the response content. In most cases, it is sufficient to store the domain of the web application in a config file and use this value whenever an absolute URL needs to be constructed. This value should be set by the administrator during the initial setup of the web application. However, such a setting can still lead to vulnerabilities if the URL is checked improperly:

```php
function check_host($host_header) {
    return str_ends_with($host_header, get_config_value('domain'));
}

function create_reset_link($user, $host_header) {
	$token = generate_reset_token($user);

	if (check_host($host_header)) {
		return "http://" . $host_header . "/pw_reset.php?token=" . $token;
	}
	
	return "http://" . get_config_value('domain') . "/pw_reset.php?token=" . $token;
}
```

In the above code, the web application uses the host header to construct a password reset link. The header is checked against a domain name stored in the web application's configuration. However, this check is conducted improperly, leading to a potential password reset poisoning vulnerability. Since it is only checked if the host header ends with the stored domain, presumably to whitelist all subdomains of the configured domain as well, an attacker can bypass this check. He can do so by registering a domain with the configured domain as a postfix. For instance, if the web application stored the domain `vulndomain.htb`, an attacker can bypass the check by setting the host header to `evilvulndomain.htb` and conducting a password reset attack by registering this domain and stealing password reset tokens.

To fix this, web applications should rely entirely on the domain stored in the configuration:

```php
function create_reset_link($user, $host_header) {
	$token = generate_reset_token($user);	
	return "http://" . get_config_value('domain') . "/pw_reset.php?token=" . $token;
}
```

This way, an attacker cannot influence the domain using the host header. If the host header is needed, it is important to perform exact validation and not only prefix or postfix checks.

## Further Remarks

To conclude this section, here are some general things to remember whenever web applications deal with the host header.

Firstly, relative URLs should be preferred whenever possible since they are unaffected by the attacks discussed in the previous sections. However, sometimes we need to use absolute URLs. For instance, in password reset emails, absolute links are required. As discussed previously, the web application's domain should be configured by the administrator during initial setup and stored in a config file. This value can then be used to construct absolute URLs whenever they are needed.

Additionally, the web server should be configured to not support any override headers. This can make potential host header attack vectors harder to exploit or prevent them entirely.

Another important thing to prevent host header attacks is to always patch issues regarding the host header, even if they seem unexploitable. Consider the following simplified example:

```php
<?php
$headers = getallheaders();
$host_header = $headers['Host'];
?>

<script src="http://<?php echo $host_header ?>/test.js"></script>
```

The web application uses the host header to construct a link for a script file. There is an obvious reflected XSS here, with a request like the following:

```http
GET /index.php HTTP/1.1
Host: 127.0.0.1"></script><script>alert(1)</script><script src="
```

However, this reflected XSS vulnerability is unexploitable on its own since there is no easy way to force the victim's browser to inject the payload into the host header. Therefore, developers may ignore the issue and won't patch it. However, this vulnerability can quickly become exploitable in combination with web cache poisoning and potentially override headers. Therefore, it is important to patch issues like this even if they seem unexploitable at first.

Lastly, host header attacks are by their nature not always exploitable since intermediary systems might reject requests or route them differently if the host header was manipulated. However, a web application should never rely on other systems' configuration to protect itself from vulnerabilities. Therefore, host header vulnerabilities need to be fixed even if they seem unlikely to be exploited in a real-world deployment setting.

