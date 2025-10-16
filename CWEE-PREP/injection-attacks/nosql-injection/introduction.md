# Introduction to NoSQL

Many applications store data in databases. Beyond relational engines, non-relational (NoSQL) databases are common. We focus on MongoDB (document-oriented, BSON).

## NoSQL Types (brief)
- Document-oriented (e.g., MongoDB, DynamoDB, Firestore)
- Key–Value (e.g., Redis)
- Wide-column (e.g., Cassandra)
- Graph (e.g., Neo4j)

## MongoDB Basics

Documents (fields → values) stored in collections:

```javascript
{
  _id: ObjectId("63651456d18bf6c01b8eeae9"),
  type: 'Granny Smith',
  price: 0.65
}
```

### Connect

```bash
mongosh mongodb://127.0.0.1:27017
```

List databases:

```javascript
show databases
```

Switch DB (created on first write):

```javascript
use academy
```

### Insert

```javascript
db.apples.insertOne({ type: 'Granny Smith', price: 0.65 })
db.apples.insertMany([
  { type: 'Golden Delicious', price: 0.79 },
  { type: 'Pink Lady', price: 0.90 }
])
```

### Query

Exact match and list all:

```javascript
db.apples.find({ type: 'Granny Smith' })
db.apples.find({})
```

Operators (examples): `$eq`, `$gt`, `$gte`, `$in`, `$lt`, `$lte`, `$nin`, `$and`, `$or`, `$not`, `$nor`, `$regex`, `$where`.

Combined example (type starts with G and price < 0.70):

```javascript
db.apples.find({
  $and: [ { type: { $regex: /^G/ } }, { price: { $lt: 0.70 } } ]
})
```

Sort and limit:

```javascript
db.apples.find({}).sort({ price: -1 }).limit(2)
```

### Update

```javascript
db.apples.updateOne({ type: 'Granny Smith' }, { $set: { price: 1.99 } })
db.apples.updateMany({}, { $inc: { quantity: 1, price: 1 } })
db.apples.replaceOne({ type: 'Pink Lady' }, { name: 'Pink Lady', price: 0.99, color: 'Pink' })
```

### Remove

```javascript
db.apples.remove({ price: { $lt: 0.8 } })
```

Next: basics of NoSQL injection and exploitation patterns.
