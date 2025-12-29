# 🗄️ Introduction to MSSQL/SQL Server

## Overview

SQL is a standardized language for interacting with relational databases.

### Top 5 Databases (Dec 2022)

| Rank | Database |
|------|----------|
| 1 | Oracle |
| 2 | MySQL |
| 3 | **Microsoft SQL Server** |
| 4 | PostgreSQL |
| 5 | IBM Db2 |

> **Note**: This module focuses on **Blind SQL Injection** using MSSQL. Techniques can be adapted to other databases since SQL is standardized.

---

## Interacting with MSSQL

### SQLCMD (Windows, Command Line)

Microsoft's command-line tool for MSSQL.

#### Connection Syntax

```powershell
sqlcmd -S 'SQL01' -U 'thomas' -P 'TopSecretPassword23!' -d bsqlintro -W
```

| Flag | Description |
|------|-------------|
| `-S` | Server name |
| `-U` | Username |
| `-P` | Password |
| `-d` | Database |
| `-W` | Remove trailing spaces |

#### Running Queries

```sql
1> SELECT * FROM INFORMATION_SCHEMA.TABLES;
2> GO
```

> **Note**: Type `GO` to execute the query batch.

#### Example Output

```
TABLE_CATALOG TABLE_SCHEMA TABLE_NAME TABLE_TYPE
------------- ------------ ---------- ----------
bsqlintro     dbo          users      BASE TABLE
bsqlintro     dbo          posts      BASE TABLE
(2 rows affected)
```

#### JOIN Query Example

```sql
SELECT TOP 5 users.firstName, users.lastName, posts.title
FROM users
JOIN posts ON users.id = posts.authorId;
GO
```

---

### Impacket-MSSQLClient (Linux, Command Line)

Part of **Impacket** toolset, preinstalled on many security distros.

#### Connection Syntax

```bash
impacket-mssqlclient thomas:'TopSecretPassword23!'@SQL01 -db bsqlintro
```

#### Running Queries

```sql
SQL> SELECT * FROM INFORMATION_SCHEMA.TABLES;

TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE
-------------   ------------   ----------   ----------
bsqlintro       dbo            users        b'BASE TABLE'
bsqlintro       dbo            posts        b'BASE TABLE'
```

#### Pentesting Features

**Enable xp_cmdshell**:

```sql
SQL> enable_xp_cmdshell
[*] INFO(SQL01): Configuration option 'xp_cmdshell' changed from 1 to 1.

SQL> xp_cmdshell whoami
output
--------------------------------------------------------------------------------
NT SERVICE\mssqlserver
NULL

SQL> exit
```

---

### SQL Server Management Studio (Windows, GUI)

Microsoft's GUI tool for MSSQL administration.

#### Workflow

1. **Connect** - Enter server name, authentication, credentials
2. **Browse** - Open `Databases` → `[database]` → `Tables`
3. **Query** - Right-click database → `New Query`
4. **Execute** - Click `Execute` button

---

## Common Enumeration Queries

### List Tables

```sql
SELECT TABLE_NAME 
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_TYPE = 'BASE TABLE';
```

### List Columns

```sql
SELECT COLUMN_NAME 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_NAME = 'users';
```

### Example Column Output

**Users table**:
```
id, username, email, firstName, lastName, password, activationKey
```

**Posts table**:
```
id, authorId, title, content
```

---

## Complex Query Example

### Requirements

Find password hash where:
1. First name begins with 'S'
2. Email > 20 characters
3. Wrote post with title starting with 'N'
4. Sorted by first name ascending

### Query

```sql
SELECT TOP 1 password 
FROM users 
JOIN posts ON posts.authorId = users.id 
WHERE firstName LIKE 'S%' 
  AND LEN(email) > 20 
  AND title LIKE 'N%' 
ORDER BY firstName ASC;
```

---

## Quick Reference

### Connection Commands

| Tool | Platform | Command |
|------|----------|---------|
| **SQLCMD** | Windows | `sqlcmd -S <server> -U <user> -P <pass> -d <db>` |
| **Impacket** | Linux | `impacket-mssqlclient <user>:'<pass>'@<server> -db <db>` |
| **SSMS** | Windows | GUI connection dialog |

### Useful SQL Syntax

| Operation | Syntax |
|-----------|--------|
| Top N rows | `SELECT TOP N ...` |
| String starts with | `LIKE 'X%'` |
| String length | `LEN(column)` |
| Join tables | `JOIN table ON condition` |
| Order results | `ORDER BY column ASC/DESC` |

---

## References

- [SQLCMD Documentation](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility)
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)
- [SQL Server Management Studio](https://docs.microsoft.com/en-us/sql/ssms/)

