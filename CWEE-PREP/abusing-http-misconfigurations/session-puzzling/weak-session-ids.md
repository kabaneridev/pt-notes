# Weak Session IDs

Even if session variables are handled correctly, attackers might be able to steal other users' sessions if the session IDs themselves are not secure. Session IDs need to be sufficiently long and unguessable to be considered secure. Otherwise, an attacker might be able to obtain another user's session ID and hijack their account by brute-forcing or guessing the session ID.

## Short Session IDs

If session IDs are not sufficiently long, an attacker can brute-force other users' active sessions and thus take over their accounts. A minimum length of 16 bytes is stated by OWASP. This assumes that session IDs are unpredictable and random. Obviously, a session ID that is 16 characters long is not secure if 12 of these characters are fixed since this would reduce the effective length down to 4 characters. This is an insufficient length that can easily be brute-forced. Let's have a look at a practical example of this.

After starting the exercise, we can see a web application with a login view. After logging in, the response contains our session ID which is only 4 characters long:

```http
HTTP POST request to /login.php on shortids.htb. Includes username htb-stdnt and password Academy_student!. Response is 302 Found, sets cookie sessionID=..., and redirects to profile.php.
```

This is of course not long enough to provide proper security. To demonstrate this, let's brute-force all possible session IDs to see if we can hijack any other logged-in user's session. From the cookie, we can deduce that the session ID consists of lowercase letters and digits.

To create a wordlist, we can use `crunch`. We can install it using:

```bash
sudo apt install crunch
```

Afterward, we can create the wordlist we want using the following command:

```bash
crunch 4 4 "abcdefghijklmnopqrstuvwxyz1234567890" -o wordlist.txt
```
For more details on the syntax of `crunch`, check out the Cracking Passwords with Hashcat module.

We can now use `ffuf` to fuzz all valid session IDs:

```bash
ffuf -u http://127.0.0.1/profile.php -b 'sessionID=FUZZ' -w wordlist.txt -fc 302 -t 10
```

We found another valid session ID. After using it in Burp, we can see that we have successfully taken over the administrator's session:

```http
HTTP GET request to /profile.php on shortids.htb with cookie sessionID=a7sh. Response shows status "logged in" with username "admin".
```

## Insufficient Randomness in Session IDs

Additionally to being sufficiently long, session IDs need to be sufficiently random. If the randomness is insufficient or there are detectable patterns in the session IDs, an attacker might be able to brute-force other users' session IDs like before. Randomness is generally measured using entropy. To be considered secure, session IDs should provide at least 64 bits of entropy according to OWASP.

If we log in to the web application, we can see that the server sets a sufficiently long session ID that looks random:

```http
HTTP POST request to /login.php on lowentropy.htb. Includes username htb-stdnt and password Academy_student!. Response is 302 Found, sets cookie sessionID=..., and redirects to profile.php.
```

To analyze the entropy of session IDs, we can use Burp Sequencer. To do so, we right-click the login request in Burp and click on `Send to Sequencer`. Afterward, switch to the `Sequencer` Tab. Make sure that Burp automatically detected the session cookie in the `Token Location Within Response` field and that the `Cookie` option is selected. We could also specify a custom location if we wanted to analyze the entropy of a different field in the response. Afterward, start the live capture.

Burp now sends a lot of login requests to the web application and captures the session IDs for analysis. We should wait for Burp to collect at least 1000 session IDs to compute a meaningful result. Afterward, we can click on `Analyze` to obtain the result of the statistical analysis of all captured session IDs.

In this case, we can see that Burp estimates the entropy of the session IDs to be about 14 bits which is significantly too low to be considered secure. In a real-world engagement, this would be a high-severity finding since this allows an attacker to brute-force active user sessions.

```text
Burp Sequencer interface showing live capture paused. Summary indicates "extremely poor" randomness with effective entropy estimated at 14 bits. Requests: 1111, Errors: 0.
```

Burp also displays a character position analysis. In this case, we can see that certain characters do not contribute to the overall entropy at all, meaning that these characters are fixed among all session IDs and not random:

```text
Graph showing usable bits of entropy for character positions. Each token converted to 14 bits, with adjustments for compression. Bars indicate bits contributed by each position.
```

