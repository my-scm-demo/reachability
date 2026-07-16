# UseCase-2 — Apache Commons Collections Deserialization RCE

A test application demonstrating reachable vulnerability patterns for BDSA-2015-0001 in `commons-collections:commons-collections:3.2.1`. The source file implements realistic usage of the InvokerTransformer gadget chain and unsafe ObjectInputStream deserialization that directly triggers the vulnerable code path.

## Vulnerabilities Covered

| BDSA | CVE | Type | Vulnerable Signature |
|---|---|---|---|
| BDSA-2015-0001 | CVE-2015-7501 | Remote Code Execution | `InvokerTransformer.transform(Object)` via deserialization gadget chain |

## Project Structure

```
UseCase-2/
├── pom.xml                                                          # Maven project — commons-collections 3.2.1
├── src/main/java/com/test/vulnerabilities/
│   └── BDSA_2015_0001.java                                          # BDSA-2015-0001: InvokerTransformer gadget chain
└── README.md
```

## BDSA Details

### BDSA-2015-0001 — CVE-2015-7501 / CVE-2015-4852: Deserialization RCE

**Component:** `commons-collections:commons-collections:3.2.1`
**Type:** Remote Code Execution via Unsafe Deserialization

Apache Commons Collections 3.x contains `InvokerTransformer`, a class that can invoke arbitrary Java methods via reflection. When combined with `ChainedTransformer` and `LazyMap`, it forms a gadget chain that enables remote code execution when a JVM deserialises an attacker-controlled payload via `ObjectInputStream.readObject()`. This was one of the original Java deserialization gadget chains made public by the ysoserial toolset.

**Affected versions:** `commons-collections < 3.2.2`
**Fix:** Upgrade to `commons-collections:3.2.2` or `commons-collections4:4.1+`

**Source file:** `BDSA_2015_0001.java`

Key patterns:

```java
// dangerous_instantiations — direct InvokerTransformer construction
new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"})

// dangerous_instantiations — chains multiple transformers
new ChainedTransformer(transformers)

// dangerous_instantiations — first link in the gadget chain
new ConstantTransformer(Runtime.class)

// enabling_or_config_apis — wraps map to trigger transformation on access
LazyMap.decorate(new HashMap<>(), chainedTransformer)

// other_relevant_patterns — deserialises untrusted input
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData))
ois.readObject()
```

---

## Building

### Build with Maven:
```bash
mvn clean package -f UseCase-2/pom.xml
```

---

## Testing Workflow

### 1. SCA Scan (Black Duck)

**Expected:** Black Duck will identify:
- Component: `commons-collections:commons-collections:3.2.1`
- Vulnerability: BDSA-2015-0001 / CVE-2015-7501

### 2. Reachability Analysis

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: llmApiKey YOUR_API_KEY" \
  -d '{
    "bdsa_ids": ["BDSA-2015-0001"],
    "source_code": {
      "BDSA_2015_0001.java": "<file contents>"
    }
  }'
```

**Expected matches:**

| BDSA | File | Reachable |
|---|---|---|
| BDSA-2015-0001 | BDSA_2015_0001.java | ✓ |

## References

- [CVE-2015-7501 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2015-7501)
- [CVE-2015-4852 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2015-4852)
- [ysoserial — Java deserialization exploit tool](https://github.com/frohoff/ysoserial)
