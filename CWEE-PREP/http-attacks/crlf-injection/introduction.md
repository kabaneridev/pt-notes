# Introduction to CRLF Injection

The term CRLF consists of the name of the two control characters Carriage Return (CR) and Line Feed (LF) that mark the beginning of a new line. CRLF injection thus refers to the injection of new lines in places where the beginning of a new line has a special semantic meaning and no proper sanitization is implemented. Examples include the injection of data into log files and the injection of headers into protocols such as HTTP or SMTP, as headers are typically separated by a newline.

## What is CRLF Injection?

The carriage return character CR (`\r`), ASCII character 13 or `0x0D` in hex and `%0D` in URL-encoding, moves the cursor to the beginning of the line. The line feed character LF (`\n`), ASCII character 10 or `0x0A` in hex and `%0A` in URL-encoding, moves the cursor down to the next line. Together they form the CRLF control sequence which denotes the beginning of a new line.

CRLF injection vulnerabilities occur where improperly sanitized user input is used in a context where newline characters have a semantically important meaning. This can be user input from input fields such as search bars, comment forms, or GET parameters. If the input is used in HTTP headers, log files, SMTP headers, or similar contexts, and the control characters CR and LF are not sanitized, CRLF injection vulnerabilities can arise.

## Impact of CRLF Injection

As discussed above, CRLF injection refers to the injection of the newline characters CR and LF. While these characters themselves do not cause any harm, they can change the semantics of a message resulting in further attack vectors. For instance, in HTTP, the headers are separated using CRLF characters. If a web application reflects user input in an HTTP header and does not properly sanitize these characters, an attacker could inject CRLF characters and add arbitrary HTTP headers to the response. This can further be escalated to an obvious reflected XSS vulnerability by changing the response body. If there are further vulnerabilities such as web cache poisoning, this can be escalated even further to target a huge number of users.

The impact of CRLF injection depends on the vulnerable web application. In some cases, it might be possible to forge log entries by injecting newlines. This allows an attacker to invalidate log files since administrators cannot be sure which entries are real and which are forged. However, this is not a high-severity vulnerability on its own. In other cases, user input might be injected into a protocol flow that treats CRLF characters as control characters just like in the example of HTTP headers discussed above. An example of this might be user input that is included in an SMTP header to set the sender of an email. This allows an attacker to inject arbitrary SMTP headers if not sanitized properly.

Generally, the impact of CRLF injection can range from a small issue to a serious security threat depending on the vulnerable web application and the context in which the vulnerability occurs.


