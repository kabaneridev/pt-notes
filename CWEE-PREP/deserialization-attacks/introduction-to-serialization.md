# Introduction to Serialization

## Introduction

**Serialization** is the process of taking an object from memory and converting it into a series of bytes so that it can be stored or transmitted over a network and then reconstructed later on, perhaps by a different program or in a different machine environment.

**Deserialization** is the reverse action: taking serialized data and reconstructing the original object in memory.

Many object-oriented programming languages support serialization natively, including:
- Java
- Ruby
- Python
- PHP
- C#

---

## PHP Serialization

Example of serializing an array in PHP:

```bash
php -a
```

```php
php > $original_data = array("HTB", 123, 7.77);
php > $serialized_data = serialize($original_data);
php > echo $serialized_data;
a:3:{i:0;s:3:"HTB";i:1;i:123;i:2;d:7.77;}
php > $reconstructed_data = unserialize($serialized_data);
php > var_dump($reconstructed_data);
array(3) {
  [0]=>
  string(3) "HTB"
  [1]=>
  int(123)
  [2]=>
  float(7.77)
}
```

### Understanding PHP Serialized Format

```php
a:3:{ // (A)rray with (3) items
    i:0;s:3:"HTB"; // (I)ndex (0); (S)tring with length (3) and value: "HTB"
    i:1;i:123; // (I)ndex (1); (I)nteger with value (123)
    i:2;d:7.77; // (I)ndex (2); (D)ouble with value (7.77)
}
```

---

## Python Serialization (Pickle)

Multiple libraries implement serialization in Python:
- **Pickle** (native)
- PyYAML
- JSONpickle

```bash
python3
```

```python
>>> import pickle
>>> original_data = ["HTB", 123, 7.77]
>>> serialized_data = pickle.dumps(original_data)
>>> print(serialized_data)
b'\x80\x04\x95\x16\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x03HTB\x94K{G@\x1f\x14z\xe1G\xae\x14e.'
>>> reconstructed_data = pickle.loads(serialized_data)
>>> print(reconstructed_data)
['HTB', 123, 7.77]
```

### Understanding Pickle Format

A pickle is a program for a virtual Pickle Machine (PM). The PM contains:
- **Stack** - Last-In-First-Out (LIFO) data structure
- **Memo** - Long-term memory for tracking already-seen objects

### Pickle Opcodes Breakdown

```python
'\x80\x04'
# PROTO 4 - Protocol version 4 (default since Python 3.8)

'\x95\x16\x00\x00\x00\x00\x00\x00\x00' 
# FRAME 16 - Data is 16 bytes long

']' 
# EMPTY_LIST - Pushes empty list onto stack

'\x94' 
# MEMOIZE - Stores top of stack in memo

'(' 
# MARK - Pushes special 'markobject' as starting point

'\x8c\x03HTB' 
# SHORT_BINUNICODE 3 HTB - Push unicode string "HTB"

'\x94' 
# MEMOIZE - Store string in memo

'K{' 
# BININT1 { - Push 1-byte unsigned int (123)

'G@\x1f\x14z\xe1G\xae\x14' 
# BINFLOAT - Push float 7.77

'e'
# APPENDS - Extend list with all items since markobject

'.' 
# STOP - End of pickle
```

---

## Quick Reference

### PHP Serialization

```php
// Serialize associative array
echo serialize(array("cereal" => "cheerios"));
// Output: a:1:{s:6:"cereal";s:8:"cheerios";}
```

### Python Pickle (Protocol 0)

```python
import pickle
pickle.dumps({"gangnam":"style"}, protocol=0).decode()
# Output: '(dp0\nVgangnam\np1\nVstyle\np2\ns.'
```

