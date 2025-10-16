# Introduction to XPath Injection

XML Path Language (XPath) is a query language for Extensible Markup Language (XML) data. We can use XPath to construct queries over XML documents. If user input is inserted into XPath queries without proper sanitization, XPath Injection vulnerabilities arise similar to SQL Injection.

## XPath Foundations
Consider the following XML document:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<academy_modules>
  <module>
    <title>Web Attacks</title>
    <author>21y4d</author>
    <tier difficulty="medium">2</tier>
    <category>offensive</category>
  </module>

  <!-- this is a comment -->
  <module>
    <title>Attacking Enterprise Networks</title>
    <author co-author="LTNB0B">mrb3n</author>
    <tier difficulty="medium">2</tier>
    <category>offensive</category>
  </module>
</academy_modules>
```

- The XML declaration specifies version and encoding (defaults: 1.0 and UTF-8 if omitted).
- XML forms a tree of nodes. Root element: `academy_modules`. Node types: element (e.g., `module`, `title`), attribute (e.g., `co-author`, `difficulty`), comment, and text nodes (e.g., `Web Attacks`).
- Each element/attribute node has exactly one parent. Elements can have many children. Nodes with the same parent are siblings. You can traverse ancestors and descendants.

## Selecting Nodes
Each XPath query selects a set of nodes from a context node (starting point). The same query can yield different results depending on the context. Base selections:

- `module` — all `module` child nodes of the context node
- `/` — the document root node
- `//` — all descendant nodes of the context node
- `.` — the context node
- `..` — the parent of the context node
- `@difficulty` — the `difficulty` attribute of the context node
- `text()` — all text node children of the context node

To avoid ambiguity, start at the document root:

- `/academy_modules/module` — `module` children of `academy_modules`
- `//module` — all `module` elements
- `/academy_modules//title` — all `title` descendants of `academy_modules`
- `/academy_modules/module/tier/@difficulty` — `difficulty` attributes of `tier` elements under the path
- `//@difficulty` — all `difficulty` attributes in the document

Note: If a query starts with `//`, it is evaluated from the document root.

## Predicates
Predicates filter results (similar to SQL `WHERE`) and are enclosed in `[]`:

- `/academy_modules/module[1]`
- `/academy_modules/module[position()=1]`
- `/academy_modules/module[last()]`
- `/academy_modules/module[position()<3]`
- `//module[tier=2]/title`
- `//module/author[@co-author]/../title`
- `//module/tier[@difficulty="medium"]/..`

Supported operands: `+`, `-`, `*`, `div`, `=`, `!=`, `<`, `<=`, `>`, `>=`, `or`, `and`, `mod`.

## Wildcards & Union
Wildcards:
- `node()` — any node
- `*` — any element node
- `@*` — any attribute node

Examples:
- `//*` — all element nodes
- `//module/author[@*]/..` — modules where `author` has at least one attribute
- `/*/*/title` — all `title` nodes exactly two levels below root

Note: `*` matches a single level, not descendants like `//`.

Union operator combines results:
- `//module[tier=2]/title/text() | //module[tier=3]/title/text()` — titles of modules in tiers 2 and 3

