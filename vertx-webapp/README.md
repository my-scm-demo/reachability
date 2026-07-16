# Vulnerable Vert.x Web Application

A test application demonstrating reachable vulnerability patterns for four BDSAs across the `io.vertx:vertx-web:4.3.7` and `io.vertx:vertx-core:4.3.7` components. Each source file is purpose-built to contain the code patterns associated with a specific BDSA, providing ground-truth positive cases for reachability analysis validation.

## Vulnerabilities Covered

| BDSA | CVE | Type | Vulnerable Signature |
|---|---|---|---|
| BDSA-2023-2163 | CVE-2023-24815 | Path Traversal | `Utils.pathOffset(String, RoutingContext)` |
| BDSA-2024-0760 | — | Connection Pool | `CombinerExecutor.submit(Executor.Action<S>)` |
| BDSA-2025-14250 | — | Directory Listing | `StaticHandlerImpl.sendDirectoryListing(...)` |
| BDSA-2025-14251 | — | Static File Serving | `StaticHandlerImpl.sendStatic(...)` |

## Project Structure

```
vertx-webapp/
├── pom.xml                                          # Maven project — vert.x-web + vert.x-core 4.3.7
├── src/main/java/com/example/vertx/
│   ├── FileServerApp.java                           # BDSA-2023-2163: StaticHandler wildcard routes
│   ├── DocumentServer.java                          # BDSA-2023-2163: StaticHandler multi-mount patterns
│   ├── HttpClientService.java                       # BDSA-2024-0760: HttpClient connection pool patterns
│   ├── DirectoryBrowserServer.java                  # BDSA-2025-14250: StaticHandler directory listing
│   └── StaticResourceServer.java                    # BDSA-2025-14251: StaticHandler sendStatic patterns
└── README.md
```

## BDSA Details

### BDSA-2023-2163 — CVE-2023-24815: Path Traversal

**Component:** `io.vertx:vertx-web:4.3.7`
**Type:** Path Traversal / Information Disclosure

`StaticHandler` with wildcard routes is vulnerable to path traversal on Windows systems. An attacker can use `\\` or `/` characters to access files outside the intended webroot.

**Source files:** `FileServerApp.java`, `DocumentServer.java`

Key patterns:
- `router.route("/*").handler(StaticHandler.create())`
- `router.route("/admin/*").handler(StaticHandler.create("admin"))`

---

### BDSA-2024-0760 — Connection Pool Race Condition

**Component:** `io.vertx:vertx-core:4.3.7`
**Type:** Connection Pool Vulnerability

Triggered through the internal `CombinerExecutor` connection pool when an `HttpClient` is created and used to make outbound requests.

**Source file:** `HttpClientService.java`

Key patterns:
- `vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true))`
- `httpClient.request(HttpMethod.GET, "http://example.com").send()`
- `router.route().handler(routingContext -> { httpClient.request(HttpMethod.GET, "http://example.com").send(); })`

---

### BDSA-2025-14250 — Directory Listing Exposure

**Component:** `io.vertx:vertx-web:4.3.7`
**Type:** Information Disclosure

Triggered when `StaticHandler` is configured with directory listing enabled, invoking `StaticHandlerImpl.sendDirectoryListing()`.

**Source file:** `DirectoryBrowserServer.java`

Key patterns:
- `router.route("/files/*").handler(StaticHandler.create().setDirectoryListing(true))`
- `router.route("/files/*").handler(StaticHandler.create("files").setDirectoryListing(true))`
- `StaticHandler.create("public").setDirectoryListing(true).handle(routingContext)`

---

### BDSA-2025-14251 — Static File Serving Vulnerability

**Component:** `io.vertx:vertx-web:4.3.7`
**Type:** Static File Serving

Triggered through `StaticHandlerImpl.sendStatic()` when a `StaticHandler` is configured and serves a static file request.

**Source file:** `StaticResourceServer.java`

Key patterns:
- `router.route("/static/*").handler(StaticHandler.create().setIncludeHidden(false))`
- `router.route("/files/*").handler(StaticHandler.create().setIncludeHidden(false).setCachingEnabled(true))`
- `StaticHandler.create().setIncludeHidden(false).handle(routingContext)`

---

## Building and Running

### Build with Maven:
```bash
mvn clean package
```

### Run the applications:
```bash
# File Server — port 8888 (BDSA-2023-2163)
java -cp target/vulnerable-file-server-1.0.0.jar com.example.vertx.FileServerApp

# Document Server — port 9999 (BDSA-2023-2163)
java -cp target/vulnerable-file-server-1.0.0.jar com.example.vertx.DocumentServer

# HTTP Client Service — port 7777 (BDSA-2024-0760)
java -cp target/vulnerable-file-server-1.0.0.jar com.example.vertx.HttpClientService

# Directory Browser — port 7070 (BDSA-2025-14250)
java -cp target/vulnerable-file-server-1.0.0.jar com.example.vertx.DirectoryBrowserServer

# Static Resource Server — port 6060 (BDSA-2025-14251)
java -cp target/vulnerable-file-server-1.0.0.jar com.example.vertx.StaticResourceServer
```

## Testing Workflow

### 1. SCA Scan (Black Duck)

**Expected:** Black Duck will identify:
- Component: `io.vertx:vertx-web:4.3.7`
- Component: `io.vertx:vertx-core:4.3.7`
- Vulnerabilities: BDSA-2023-2163, BDSA-2024-0760, BDSA-2025-14250, BDSA-2025-14251

### 2. Reachability Analysis (Noodle)

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: llmApiKey YOUR_API_KEY" \
  -d '{
    "bdsa_ids": ["BDSA-2023-2163", "BDSA-2024-0760", "BDSA-2025-14250", "BDSA-2025-14251"],
    "source_code": {
      "FileServerApp.java": "<file contents>",
      "DocumentServer.java": "<file contents>",
      "HttpClientService.java": "<file contents>",
      "DirectoryBrowserServer.java": "<file contents>",
      "StaticResourceServer.java": "<file contents>"
    }
  }'
```

**Expected matches:**

| BDSA | File | Reachable |
|---|---|---|
| BDSA-2023-2163 | FileServerApp.java | ✓ |
| BDSA-2023-2163 | DocumentServer.java | ✓ |
| BDSA-2024-0760 | HttpClientService.java | ✓ |
| BDSA-2025-14250 | DirectoryBrowserServer.java | ✓ |
| BDSA-2025-14251 | StaticResourceServer.java | ✓ |

## References

- [CVE-2023-24815 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-24815)
- [Vert.x Security Advisory — GHSA-53jx-vvf9-4x38](https://github.com/advisories/GHSA-53jx-vvf9-4x38)
