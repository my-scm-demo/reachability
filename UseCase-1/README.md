# UseCase-1 — Keycloak OIDC Identity Brokering

A test application demonstrating reachable vulnerability patterns for BDSA-2024-2150 in `org.keycloak:keycloak-core:22.0.9`. The source file implements a realistic Keycloak SPI backchannel logout handler that directly invokes the vulnerable JWT validation path.

## Vulnerabilities Covered

| BDSA | CVE | Type | Vulnerable Signature |
|---|---|---|---|
| BDSA-2024-2150 | CVE-2023-0657 | Improper Authorization | `OIDCIdentityProvider.validateJwt(EventBuilder, String, String)` |

## Project Structure

```
UseCase-1/
├── pom.xml                                                          # Maven project — keycloak-core 22.0.9
├── src/main/java/com/test/vulnerabilities/
│   └── BDSA_2024_2150.java                                          # BDSA-2024-2150: OIDCIdentityProvider JWT validation
└── README.md
```

## BDSA Details

### BDSA-2024-2150 — CVE-2023-0657: Improper Authorization

**Component:** `org.keycloak:keycloak-core:22.0.9`
**Type:** Improper Authorization / JWT Validation Bypass

In Keycloak's identity brokering flow, `OIDCIdentityProvider.validateJwt()` is used to validate JWT tokens received from upstream OIDC providers. An attacker can exploit insufficient authorization checks during this validation to perform token injection or session hijacking via a manipulated backchannel logout request.

**Source file:** `BDSA_2024_2150.java`

Key patterns:

```java
// enabling_or_config_apis — retrieves OIDC provider from session
keycloakSession.getProvider(OIDCIdentityProvider.class)

// enabling_or_config_apis — configures signature validation before invoking provider
identityProviderConfig.setValidateSignature(true)

// dangerous_instantiations — constructs OIDCIdentityProvider directly
new OIDCIdentityProvider(keycloakSession, identityProviderConfig)

// other_relevant_patterns — direct invocation of the vulnerable signature
oidcIdentityProvider.validateJwt(eventBuilder, logoutToken, clientId)
identityProvider.validateJwt(eventBuilder, tokenString, clientId)
```

---

## Building

### Build with Maven:
```bash
mvn clean package -f UseCase-1/pom.xml
```

---

## Testing Workflow

### 1. SCA Scan (Black Duck)

**Expected:** Black Duck will identify:
- Component: `org.keycloak:keycloak-core:22.0.9`
- Vulnerability: BDSA-2024-2150 / CVE-2023-0657

### 2. Reachability Analysis

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: llmApiKey YOUR_API_KEY" \
  -d '{
    "bdsa_ids": ["BDSA-2024-2150"],
    "source_code": {
      "BDSA_2024_2150.java": "<file contents>"
    }
  }'
```

**Expected matches:**

| BDSA | File | Reachable |
|---|---|---|
| BDSA-2024-2150 | BDSA_2024_2150.java | ✓ |

## References

- [CVE-2023-0657 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-0657)
- [Keycloak Security Advisory — GHSA-4p8r-4qw7-g4r4](https://github.com/advisories/GHSA-4p8r-4qw7-g4r4)
