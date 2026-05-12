# MidPoint ZIdentity Connector

<p align="center">
  <img src="https://img.shields.io/badge/MidPoint-ConnId-0082C8?style=for-the-badge&logo=evolveum&logoColor=white" alt="MidPoint">
  <img src="https://img.shields.io/badge/Zscaler-ZIdentity-003366?style=for-the-badge&logo=zscaler&logoColor=white" alt="ZIdentity">
  <img src="https://img.shields.io/badge/Java-11%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" alt="Java">
  <img src="https://img.shields.io/badge/OAuth2-client__credentials-green?style=for-the-badge" alt="OAuth2">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/stars/paoloamato2/midpoint-zidentity-connector?style=for-the-badge" alt="Stars">
</p>

<p align="center">
  <strong>A <a href="https://connid.tirasa.net">ConnId</a> connector for <a href="https://evolveum.com/midpoint/">Evolveum MidPoint</a> that integrates with <a href="https://help.zscaler.com/zidentity">Zscaler ZIdentity</a>.<br>
  Full CRUD for Users and Groups via the ZIdentity Admin REST API, authenticated with OAuth 2.0 <code>client_credentials</code>.</strong>
</p>

---

## Table of Contents

- [Features](#features)
- [Supported Operations](#supported-operations)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
  - [1. Create an API client in ZIdentity](#1-create-an-api-client-in-zidentity)
  - [2. Build the connector JAR](#2-build-the-connector-jar)
  - [3. Install in MidPoint](#3-install-in-midpoint)
  - [4. Configure the resource in MidPoint](#4-configure-the-resource-in-midpoint)
- [Configuration Properties](#configuration-properties)
- [Schema](#schema)
  - [User (\_\_ACCOUNT\_\_)](#user-__account__)
  - [Group](#group)
- [Group Membership](#group-membership)
- [Project Structure](#project-structure)
- [Building & Testing](#building--testing)
- [Security Notes](#security-notes)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Full CRUD** for ZIdentity Users (`__ACCOUNT__`) and Groups
- **OAuth 2.0 `client_credentials`** authentication with automatic token caching and refresh
- **Paginated list operations** - streams pages to avoid loading all records in memory
- **Group membership reconciliation** - diff-based add/remove with minimal API calls
- **UpdateDelta** support - incremental attribute updates without full replace
- **Configurable SSL verification** - disable only in non-production environments
- Implements `TestOp`, `SchemaOp`, `CreateOp`, `DeleteOp`, `SearchOp`, `UpdateOp`, `UpdateDeltaOp`

---

## Supported Operations

| Operation | User (`__ACCOUNT__`) | Group |
|---|:---:|:---:|
| **Test connection** | ✅ | - |
| **Schema** | ✅ | ✅ |
| **Create** | ✅ | ✅ |
| **Read / Search** | ✅ | ✅ |
| **Update (full)** | ✅ | ✅ |
| **Update (delta)** | ✅ | ✅ |
| **Delete** | ✅ | ✅ |

---

## Requirements

| Requirement | Version |
|---|---|
| Java | 9+ |
| Maven | 3.6+ |
| MidPoint | 4.x (ConnId 1.5+) |
| ZIdentity | Any version exposing Admin REST API v1 |

---

## Quick Start

### 1. Create an API client in ZIdentity

1. Log into the **ZIdentity Admin Console**
2. Navigate to **Integration > API Clients**
3. Click **Add API Client** and assign the minimum required permissions:
   - `Users: Read / Write`
   - `Groups: Read / Write`
4. Note the **Client ID** and **Client Secret** - the secret is shown only once

### 2. Build the connector JAR

```bash
git clone https://github.com/paoloamato2/midpoint-zidentity-connector.git
cd midpoint-zidentity-connector

mvn clean package -DskipTests
```

The connector bundle is produced at:

```
target/zidentity-1.0-connector.jar
```

### 3. Install in MidPoint

Copy the JAR to MidPoint's connector directory and restart:

```bash
cp target/zidentity-1.0-connector.jar /opt/midpoint/var/connid-connectors/
# then restart MidPoint
```

MidPoint will auto-detect the connector on the next startup or after a **Refresh connector list** in the UI.

### 4. Configure the resource in MidPoint

Create a new **Resource** in MidPoint and select the `Zscaler ZIdentity` connector. Set the following configuration properties:

| Property | Example value |
|---|---|
| Tenant | `acme` |
| API Client ID | `<your-client-id>` |
| API Client Secret | `<your-client-secret>` *(confidential)* |
| Verify SSL Certificate | `true` |
| Fetch Group Memberships | `true` |
| Page Size | `200` |

---

## Configuration Properties

| Property | Type | Required | Default | Description |
|---|---|:---:|---|---|
| `tenant` | String | ✅ | - | Zscaler tenant name. If the login URL is `https://acme.zslogin.net`, enter `acme`. |
| `clientId` | String | ✅ | - | OAuth2 client ID from the ZIdentity admin console. |
| `clientSecret` | GuardedString | ✅ | - | OAuth2 client secret. Stored encrypted. |
| `sslVerify` | Boolean | - | `true` | Verify the TLS certificate of Zscaler endpoints. Disable only in non-production. |
| `fetchGroupMemberships` | Boolean | - | `true` | Fetch group memberships for every user during list operations (one extra API call per user). Disable for better performance if group data is managed via the Group object class. |
| `pageSize` | Integer | - | `200` | Records per page for paginated list calls (1-1000). |

---

## Schema

### User (`__ACCOUNT__`)

| ConnId Attribute | Type | Writable | Description |
|---|---|:---:|---|
| `__UID__` | String | ❌ | System-assigned user ID (`id` field) |
| `__NAME__` | String | ✅ | Unique login name (`loginName`) |
| `__ENABLE__` | Boolean | ✅ | Account status (active/inactive) |
| `__PASSWORD__` | GuardedString | ✅ | User password (write-only) |
| `displayName` | String | ✅ | Display name |
| `firstName` | String | ✅ | First name |
| `lastName` | String | ✅ | Last name |
| `primaryEmail` | String | ✅ | Primary email address |
| `secondaryEmail` | String | ✅ | Secondary email address |
| `departmentId` | String | ✅ | Department ID (maps to `department.id`) |
| `source` | String | ❌ | Identity source (read-only metadata) |
| `groups` | ConnectorObjectReference[] | ✅ | Multi-valued group memberships (SUBJECT role) |

### Group

| ConnId Attribute | Type | Writable | Description |
|---|---|:---:|---|
| `__UID__` | String | ❌ | System-assigned group ID |
| `__NAME__` | String | ✅ | Group name |
| `description` | String | ✅ | Group description |
| `isDynamicGroup` | Boolean | ❌ | Whether the group uses dynamic rules |
| `source` | String | ❌ | Identity source (read-only metadata) |
| `members` | String[] | ❌ | Member user IDs (read-only, populated on single-group reads) |

---

## Group Membership

Group memberships are exposed as a multi-valued `ConnectorObjectReference` attribute named `groups` on `__ACCOUNT__`.

**How it works:**

- **Create / UpdateOp (full replace):** all desired group IDs are reconciled against the current state - missing memberships are added, extra ones are removed.
- **UpdateDeltaOp (incremental):**
  - `valuesToAdd` → calls `POST /groups/{id}/users/{userId}`
  - `valuesToRemove` → calls `DELETE /groups/{id}/users/{userId}`
  - `valuesToReplace` → full reconciliation diff

> **Performance tip:** Set `fetchGroupMemberships = false` if you manage group memberships exclusively through the `Group` object class in MidPoint. This avoids one extra API call per user during full list operations.

---

## Project Structure

```
midpoint-zidentity-connector/
├── pom.xml                                          # Maven build descriptor
├── src/
│   ├── main/
│   │   ├── assembly/
│   │   │   └── connector.xml                        # Maven Assembly descriptor (connector bundle)
│   │   ├── java/com/example/midpoint/zidentity/
│   │   │   ├── ZIdentityClient.java                 # HTTP client: OAuth2, pagination, CRUD
│   │   │   ├── ZIdentityConfiguration.java          # ConnId configuration properties
│   │   │   ├── ZIdentityConnector.java              # ConnId connector implementation
│   │   │   └── package-info.java
│   │   └── resources/com/example/midpoint/zidentity/
│   │       └── Messages.properties                  # UI display strings
│   └── test/
│       └── java/com/example/midpoint/zidentity/
│           ├── ZIdentityConfigurationTest.java       # Configuration validation tests
│           ├── ZIdentityConnectorSchemaTest.java     # Schema definition tests
│           └── ZIdentityClientTest.java              # HTTP client tests (MockWebServer)
└── .github/
    └── workflows/
        ├── ci.yml                                   # Build & test on every push/PR
        └── release.yml                              # Build & publish connector JAR on tag
```

---

## Building & Testing

```bash
# Run unit tests
mvn test

# Build the connector bundle (skipping tests)
mvn clean package -DskipTests

# Build + run tests
mvn clean verify
```

The test suite uses **JUnit 5** and **OkHttp MockWebServer** — no real ZIdentity tenant is required.

---

## Security Notes

- The API client secret is stored as a `GuardedString` (encrypted at rest by MidPoint) and is wiped from memory immediately after use.
- Set `sslVerify = true` in production to prevent MITM attacks.
- Follow the **principle of least privilege**: assign only `Users: Read/Write` and `Groups: Read/Write` to the API client — avoid super-admin credentials.
- **Never commit your client secret** in XML resource definitions or logs.
- Rotate the API client secret regularly and revoke it immediately if compromised.

---

## Contributing

Contributions are welcome! Please open an issue before submitting a pull request.

- Bug reports and feature requests → [open an issue](https://github.com/paoloamato2/midpoint-zidentity-connector/issues)

---

## License

This project is licensed under the **Apache License 2.0** — see [LICENSE](LICENSE) for details.

> **Disclaimer:** This project is not affiliated with or endorsed by Zscaler, Inc. or Evolveum s.r.o.
