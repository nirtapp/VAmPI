# API Security Audit Report

> **Target**: VAmPI (The Vulnerable API)
> **Date**: 2026-02-15
> **Auditor**: Claude Code AI Security Audit
> **Framework**: OWASP API Security Top 10 (2023)

---

## Executive Summary

VAmPI was assessed against the OWASP API Security Top 10 (2023) framework. The audit combined automated static analysis, manual code review, and OWASP compliance assessment. The application is an intentionally vulnerable Flask/Connexion REST API with a toggleable `vuln` flag — however, several vulnerabilities exist regardless of this flag.

### Risk Overview

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 3 |
| Medium | 4 |
| Low | 5 |
| Informational | 0 |
| **Total** | **16** |

### Key Findings
1. **SQL Injection** in user lookup via f-string interpolation allows full database compromise
2. **Plaintext password storage** — no hashing applied to any user passwords
3. **Unauthenticated debug endpoint** exposes all usernames, passwords, emails, and admin status
4. **Hardcoded JWT secret** (`'random'`) allows token forgery by any attacker
5. **Broken Object Level Authorization** on password update and book retrieval endpoints

---

## Scope & Methodology

### Target Information
- **Application**: VAmPI (The Vulnerable API)
- **Type**: REST API
- **Framework**: Flask 2.2.2 + Connexion 2.14.2 (OpenAPI 3.0)
- **Language**: Python 3
- **Authentication**: JWT Bearer tokens (PyJWT 2.6.0)
- **Database**: SQLite via SQLAlchemy 2.0.2
- **Vulnerability Toggle**: `vuln` env var (default: 1 = vulnerable)

### Methodology
- [x] Static code analysis (automated + manual)
- [x] OWASP API Security Top 10 compliance review
- [x] Manual code review
- [x] OpenAPI spec vs implementation comparison

### Endpoints Tested

| # | Method | Path | Auth | Description |
|---|--------|------|------|-------------|
| 1 | GET | `/` | No | API home/info |
| 2 | GET | `/createdb` | No | Drop & recreate database |
| 3 | GET | `/users/v1` | No | List all users |
| 4 | GET | `/users/v1/_debug` | No | List all users with passwords |
| 5 | GET | `/users/v1/{username}` | No | Get user by username |
| 6 | GET | `/me` | Yes | Get current authenticated user |
| 7 | POST | `/users/v1/register` | No | Register new user |
| 8 | POST | `/users/v1/login` | No | Login and get JWT token |
| 9 | PUT | `/users/v1/{username}/email` | Yes | Update user email |
| 10 | PUT | `/users/v1/{username}/password` | Yes | Update user password |
| 11 | DELETE | `/users/v1/{username}` | Yes | Delete user (admin only) |
| 12 | GET | `/books/v1` | No | List all books |
| 13 | POST | `/books/v1` | Yes | Add new book |
| 14 | GET | `/books/v1/{book_title}` | Yes | Get book by title |

---

## Findings Summary

| # | Title | Severity | OWASP | CWE | Location | Fix |
|---|-------|----------|-------|-----|----------|-----|
| 1 | SQL Injection via f-string | Critical | API8 | CWE-89 | `models/user_model.py:72` | Yes |
| 2 | Hardcoded JWT Secret Key | Critical | API2 | CWE-798 | `config.py:13` | Yes |
| 3 | Plaintext Password Storage | Critical | API2 | CWE-256 | `models/user_model.py:24` | Yes |
| 4 | Unauthenticated Debug Endpoint | Critical | API3 | CWE-213 | `api_views/users.py:24` | Yes |
| 5 | BOLA: Unauthorized Password Change | High | API1 | CWE-639 | `api_views/users.py:186-189` | Yes |
| 6 | BOLA: Book Access Without Ownership Check | High | API1 | CWE-639 | `api_views/books.py:50-51` | Yes |
| 7 | Mass Assignment: Admin Privilege Escalation | High | API3 | CWE-915 | `api_views/users.py:60-66` | Yes |
| 8 | User/Password Enumeration | Medium | API2 | CWE-204 | `api_views/users.py:101-106` | Yes |
| 9 | ReDoS in Email Validation | Medium | API4 | CWE-1333 | `api_views/users.py:144-145` | Yes |
| 10 | Unauthenticated Database Reset | Medium | API5 | CWE-285 | `api_views/main.py:6-12` | Yes |
| 11 | No Rate Limiting | Medium | API4 | CWE-770 | Global | Manual |
| 12 | Debug Mode Enabled | Low | API8 | CWE-489 | `app.py:17` | Yes |
| 13 | Bare Except: login_user | Low | API8 | CWE-396 | `api_views/users.py:113` | Yes |
| 14 | Bare Except: token_validator | Low | API8 | CWE-396 | `api_views/users.py:121` | Yes |
| 15 | Bare Except: update_email | Low | API8 | CWE-396 | `api_views/users.py:136` | Yes |
| 16 | Bare Except: add_new_book | Low | API8 | CWE-396 | `api_views/books.py:21` | Yes |

---

## Detailed Findings

### Finding 1: SQL Injection via f-string

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **CVSS Score** | 9.8 |
| **OWASP Category** | API8 - Security Misconfiguration |
| **CWE** | CWE-89 |
| **Location** | `models/user_model.py:72` |

**Description:**
The `get_user()` method constructs a SQL query using an f-string with unsanitized user input. An attacker can inject arbitrary SQL via the `username` parameter, leading to full database compromise including credential extraction, data modification, and potential remote code execution.

**Evidence:**
```python
if vuln:  # SQLi Injection
    user_query = f"SELECT * FROM users WHERE username = '{username}'"
    query = db.session.execute(text(user_query))
```

**Impact:**
An attacker can extract all user credentials, modify data, or delete the entire database by crafting a malicious username parameter (e.g., `' OR 1=1 --`).

**Remediation:**
```python
user_query = text("SELECT * FROM users WHERE username = :username")
query = db.session.execute(user_query, {"username": username})
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- https://cwe.mitre.org/data/definitions/89.html

---

### Finding 2: Hardcoded JWT Secret Key

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **CVSS Score** | 9.1 |
| **OWASP Category** | API2 - Broken Authentication |
| **CWE** | CWE-798 |
| **Location** | `config.py:13` |

**Description:**
The JWT signing secret is hardcoded as the string `'random'`. Any attacker who knows this value (which is in the source code) can forge valid JWT tokens for any user, including admin accounts.

**Evidence:**
```python
vuln_app.app.config['SECRET_KEY'] = 'random'
```

**Impact:**
Complete authentication bypass. An attacker can forge tokens for any user including admin, gaining full access to all API functionality.

**Remediation:**
```python
import os
secret = os.environ.get('SECRET_KEY')
if not secret or len(secret) < 32:
    raise RuntimeError("SECRET_KEY env var must be set (min 32 chars)")
vuln_app.app.config['SECRET_KEY'] = secret
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- https://cwe.mitre.org/data/definitions/798.html

---

### Finding 3: Plaintext Password Storage

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **CVSS Score** | 9.1 |
| **OWASP Category** | API2 - Broken Authentication |
| **CWE** | CWE-256 |
| **Location** | `models/user_model.py:24` |

**Description:**
Passwords are stored in the database as plaintext. The `User.__init__` method directly assigns `self.password = password` without any hashing. Login comparison is also done via plaintext comparison (`request_data.get('password') == user.password`).

**Evidence:**
```python
def __init__(self, username, password, email, admin=False):
    self.username = username
    self.email = email
    self.password = password  # No hashing!
    self.admin = admin
```

**Impact:**
If the database is compromised (e.g., via SQL injection Finding #1), all user passwords are immediately exposed in cleartext. Combined with password reuse, this can lead to compromise of user accounts on other services.

**Remediation:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

def __init__(self, username, password, email, admin=False):
    self.username = username
    self.email = email
    self.password = generate_password_hash(password)
    self.admin = admin

# In login_user():
if user and check_password_hash(user.password, request_data.get('password')):
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- https://cwe.mitre.org/data/definitions/256.html

---

### Finding 4: Unauthenticated Debug Endpoint Exposing All Credentials

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **CVSS Score** | 9.8 |
| **OWASP Category** | API3 - Broken Object Property Level Authorization |
| **CWE** | CWE-213 |
| **Location** | `api_views/users.py:24-26` |

**Description:**
The `/users/v1/_debug` endpoint returns all user records including plaintext passwords, email addresses, and admin status. It requires no authentication and is accessible regardless of the `vuln` flag.

**Evidence:**
```python
def debug():
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value

# User.get_all_users_debug() returns:
# {'username': ..., 'password': ..., 'email': ..., 'admin': ...}
```

**Impact:**
Any unauthenticated attacker can retrieve all user credentials, email addresses, and admin status with a single GET request.

**Remediation:**
```python
import os

def debug():
    if os.environ.get('FLASK_ENV') != 'development':
        return Response('{"status":"fail","message":"Not found"}', 404, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Admin access required"), 403, mimetype="application/json")
    return jsonify({'users': User.get_all_users_debug()})
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- https://cwe.mitre.org/data/definitions/213.html

---

### Finding 5: BOLA — Unauthorized Password Change

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **CVSS Score** | 8.1 |
| **OWASP Category** | API1 - Broken Object Level Authorization |
| **CWE** | CWE-639 |
| **Location** | `api_views/users.py:186-189` |

**Description:**
When `vuln=1`, the `update_password` function uses the `username` path parameter instead of the authenticated user's identity from the JWT token. Any authenticated user can change any other user's password.

**Evidence:**
```python
if vuln:  # Unauthorized update of password of another user
    user = User.query.filter_by(username=username).first()  # Uses path param!
    if user:
        user.password = request_data.get('password')
```

**Impact:**
Any authenticated user can change any other user's password, including admin accounts, leading to full account takeover.

**Remediation:**
```python
# Always derive identity from the token, not the path parameter
user = User.query.filter_by(username=resp['sub']).first()
user.password = request_data.get('password')
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- https://cwe.mitre.org/data/definitions/639.html

---

### Finding 6: BOLA — Book Access Without Ownership Check

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **CVSS Score** | 7.5 |
| **OWASP Category** | API1 - Broken Object Level Authorization |
| **CWE** | CWE-639 |
| **Location** | `api_views/books.py:50-51` |

**Description:**
When `vuln=1`, the `get_by_title` function retrieves any book by title without verifying that the requesting user is the owner. This exposes `secret_content` belonging to other users.

**Evidence:**
```python
if vuln:  # Broken Object Level Authorization
    book = Book.query.filter_by(book_title=str(book_title)).first()  # No ownership check
```

**Impact:**
Any authenticated user can read the secret content of any other user's books by guessing or enumerating book titles.

**Remediation:**
```python
user = User.query.filter_by(username=resp['sub']).first()
book = Book.query.filter_by(book_title=str(book_title), user_id=user.id).first()
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- https://cwe.mitre.org/data/definitions/639.html

---

### Finding 7: Mass Assignment — Admin Privilege Escalation

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **CVSS Score** | 8.1 |
| **OWASP Category** | API3 - Broken Object Property Level Authorization |
| **CWE** | CWE-915 |
| **Location** | `api_views/users.py:60-66` |

**Description:**
When `vuln=1`, the registration endpoint accepts an `admin` field from the request body and uses it to set the user's admin privilege. Any user can register as an admin.

**Evidence:**
```python
if vuln and 'admin' in request_data:
    if request_data['admin']:
        admin = True
    else:
        admin = False
    user = User(username=..., password=..., email=..., admin=admin)
```

**Impact:**
Any unauthenticated user can register with admin privileges by including `"admin": true` in the registration request body, gaining full administrative access.

**Remediation:**
```python
# Never accept admin field from client input
user = User(username=request_data['username'], password=request_data['password'],
            email=request_data['email'], admin=False)
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- https://cwe.mitre.org/data/definitions/915.html

---

### Finding 8: User/Password Enumeration

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **CVSS Score** | 5.3 |
| **OWASP Category** | API2 - Broken Authentication |
| **CWE** | CWE-204 |
| **Location** | `api_views/users.py:101-106` |

**Description:**
When `vuln=1`, the login endpoint returns different error messages for invalid username vs invalid password, allowing attackers to enumerate valid usernames.

**Evidence:**
```python
if vuln:
    if user and request_data.get('password') != user.password:
        return Response(error_message_helper("Password is not correct for the given username."), ...)
    elif not user:
        return Response(error_message_helper("Username does not exist"), ...)
```

**Impact:**
Attackers can determine which usernames are valid, then focus brute-force attacks on those accounts.

**Remediation:**
```python
if not user or request_data.get('password') != user.password:
    return Response(error_message_helper("Invalid credentials"), 401, mimetype="application/json")
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- https://cwe.mitre.org/data/definitions/204.html

---

### Finding 9: ReDoS in Email Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **CVSS Score** | 5.3 |
| **OWASP Category** | API4 - Unrestricted Resource Consumption |
| **CWE** | CWE-1333 |
| **Location** | `api_views/users.py:144-145` |

**Description:**
When `vuln=1`, the email update endpoint uses a regex pattern with nested quantifiers that is vulnerable to catastrophic backtracking (ReDoS).

**Evidence:**
```python
match = re.search(
    r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
    str(request_data.get('email')))
```

**Impact:**
An attacker can send a specially crafted email string that causes the regex engine to consume excessive CPU time, potentially causing denial of service.

**Remediation:**
```python
# Use a simple regex or a dedicated library
import re
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
match = EMAIL_RE.match(str(request_data.get('email')))
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- https://cwe.mitre.org/data/definitions/1333.html

---

### Finding 10: Unauthenticated Database Reset

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **CVSS Score** | 6.5 |
| **OWASP Category** | API5 - Broken Function Level Authorization |
| **CWE** | CWE-285 |
| **Location** | `api_views/main.py:6-12` |

**Description:**
The `/createdb` endpoint drops all database tables and recreates them with default data. It requires no authentication and is accessible to anyone.

**Evidence:**
```python
def populate_db():
    db.drop_all()
    db.create_all()
    User.init_db_users()
```

**Impact:**
Any unauthenticated user can wipe the entire database at any time, causing complete data loss.

**Remediation:**
```python
def populate_db():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Admin access required"), 403, mimetype="application/json")
    db.drop_all()
    db.create_all()
    User.init_db_users()
    response_text = '{ "message": "Database populated." }'
    return Response(response_text, 200, mimetype='application/json')
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- https://cwe.mitre.org/data/definitions/285.html

---

### Finding 11: No Rate Limiting

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **CVSS Score** | 5.3 |
| **OWASP Category** | API4 - Unrestricted Resource Consumption |
| **CWE** | CWE-770 |
| **Location** | Global (all endpoints) |

**Description:**
No rate limiting is implemented on any endpoint. The login endpoint is particularly vulnerable to brute-force attacks.

**Evidence:**
No rate limiting middleware (Flask-Limiter or equivalent) is present in `requirements.txt` or application code.

**Impact:**
Attackers can perform unrestricted brute-force attacks against the login endpoint, or flood any endpoint to cause denial of service.

**Remediation:**
```python
# Add flask-limiter to requirements.txt
# In app.py:
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app=vuln_app.app, key_func=get_remote_address, default_limits=["100/hour"])

# On login endpoint:
@limiter.limit("5/minute")
def login_user():
    ...
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- https://cwe.mitre.org/data/definitions/770.html

---

### Finding 12: Debug Mode Enabled

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **CVSS Score** | 3.7 |
| **OWASP Category** | API8 - Security Misconfiguration |
| **CWE** | CWE-489 |
| **Location** | `app.py:17` |

**Description:**
Flask debug mode is enabled with `debug=True`, which exposes detailed stack traces and enables the interactive debugger in production.

**Evidence:**
```python
vuln_app.run(host='0.0.0.0', port=5000, debug=True)
```

**Impact:**
Stack traces reveal internal code paths, file locations, and variable values. The Werkzeug debugger can potentially allow remote code execution.

**Remediation:**
```python
import os
vuln_app.run(host='0.0.0.0', port=5000, debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
```

**References:**
- https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- https://cwe.mitre.org/data/definitions/489.html

---

### Finding 13: Bare Except — login_user

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **CVSS Score** | 2.0 |
| **OWASP Category** | API8 - Security Misconfiguration |
| **CWE** | CWE-396 |
| **Location** | `api_views/users.py:113` |

**Description:**
Bare `except:` clause catches all exceptions including `SystemExit` and `KeyboardInterrupt`, potentially masking critical errors.

**Evidence:**
```python
except:
    return Response(error_message_helper("An error occurred!"), 200, mimetype="application/json")
```

**Remediation:**
```python
except Exception as e:
    return Response(error_message_helper("An error occurred!"), 500, mimetype="application/json")
```

---

### Finding 14: Bare Except — token_validator

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **CVSS Score** | 2.0 |
| **OWASP Category** | API8 - Security Misconfiguration |
| **CWE** | CWE-396 |
| **Location** | `api_views/users.py:121` |

**Description:**
Bare `except:` in token parsing.

**Evidence:**
```python
try:
    auth_token = auth_header.split(" ")[1]
except:
    auth_token = ""
```

**Remediation:**
```python
except (IndexError, AttributeError):
    auth_token = ""
```

---

### Finding 15: Bare Except — update_email

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **CVSS Score** | 2.0 |
| **OWASP Category** | API8 - Security Misconfiguration |
| **CWE** | CWE-396 |
| **Location** | `api_views/users.py:136` |

**Description:**
Bare `except:` in JSON schema validation.

**Evidence:**
```python
except:
    return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
```

**Remediation:**
```python
except jsonschema.exceptions.ValidationError as exc:
    return Response(error_message_helper(exc.message), 400, mimetype="application/json")
```

---

### Finding 16: Bare Except — add_new_book

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **CVSS Score** | 2.0 |
| **OWASP Category** | API8 - Security Misconfiguration |
| **CWE** | CWE-396 |
| **Location** | `api_views/books.py:21` |

**Description:**
Bare `except:` in JSON schema validation.

**Evidence:**
```python
except:
    return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
```

**Remediation:**
```python
except jsonschema.exceptions.ValidationError as exc:
    return Response(error_message_helper(exc.message), 400, mimetype="application/json")
```

---

## OWASP API Security Top 10 Compliance Matrix

| # | Category | Status | Findings |
|---|----------|--------|----------|
| API1 | Broken Object Level Authorization | FAIL | #5 (BOLA password), #6 (BOLA books) |
| API2 | Broken Authentication | FAIL | #2 (hardcoded secret), #3 (plaintext passwords), #8 (enumeration) |
| API3 | Broken Object Property Level Authorization | FAIL | #4 (debug endpoint), #7 (mass assignment) |
| API4 | Unrestricted Resource Consumption | FAIL | #9 (ReDoS), #11 (no rate limiting) |
| API5 | Broken Function Level Authorization | FAIL | #10 (unauth DB reset) |
| API6 | Unrestricted Access to Sensitive Business Flows | PASS | No automated business flow abuse detected |
| API7 | Server Side Request Forgery | PASS | No URL-fetching endpoints found |
| API8 | Security Misconfiguration | FAIL | #1 (SQLi), #12 (debug mode), #13-16 (bare excepts) |
| API9 | Improper Inventory Management | FAIL | Debug endpoint (#4) exposed in production spec |
| API10 | Unsafe Consumption of APIs | N/A | No external API consumption detected |

---

## Recommendations

### Immediate Actions (Critical/High — within 48 hours)
1. Replace f-string SQL with parameterized queries (Finding #1)
2. Move SECRET_KEY to environment variable with minimum 32-char value (Finding #2)
3. Hash all passwords with werkzeug/bcrypt (Finding #3)
4. Remove or gate `/users/v1/_debug` behind admin auth + dev environment check (Finding #4)
5. Fix BOLA on password update — use token identity, not path param (Finding #5)
6. Fix BOLA on books — add ownership check (Finding #6)
7. Remove `admin` field acceptance from registration (Finding #7)

### Short-Term (Medium — within 1 month)
1. Implement unified "Invalid credentials" error message (Finding #8)
2. Replace vulnerable email regex with simple pattern (Finding #9)
3. Add authentication + admin check to `/createdb` (Finding #10)
4. Add rate limiting via Flask-Limiter (Finding #11)

### Long-Term (Low — within 1 quarter)
1. Disable debug mode in production (Finding #12)
2. Replace all bare `except:` with specific exception types (Findings #13-16)
3. Add security headers (HSTS, X-Content-Type-Options, X-Frame-Options)
4. Implement proper CORS policy

---

## Appendix

### A. Tools Used
- Static analysis: `scripts/analyze_api.py` (14 automated findings)
- Manual review: Full code walkthrough of all Python source files
- OpenAPI spec comparison: `openapi_specs/openapi3.yml` vs actual implementation

### B. Testing Environment
- VAmPI source code at `/home/user/Mytools/DEV/VAmPI/`
- Vulnerability flag: `vuln=1` (default, vulnerable mode)
- Python dependencies per `requirements.txt`

### C. Remediation Status

| Fix Status | Meaning |
|------------|---------|
| **Yes** | Automated fix applied in the security fix PR |
| **Manual** | Requires human decision or new dependency — documented in PR |
| **No** | Not fixable automatically (architectural/business logic change needed) |

**Fix Branch**: `fix/security-audit-2026-02-15`
**PR**: (pending)

### D. Disclaimer
This audit was performed based on available source code and/or dynamic testing at a point in time. It does not guarantee the absence of all vulnerabilities. New vulnerabilities may be discovered as the application evolves.
