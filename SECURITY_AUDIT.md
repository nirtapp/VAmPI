# API Security Audit Report

**Project:** VAmPI (Vulnerable API)
**Date:** 2026-02-15
**Auditor:** Claude Code — API Security Audit Skill

---

## Executive Summary

VAmPI is an intentionally vulnerable REST API built with Flask and Connexion (OpenAPI 3.0), designed for security testing tool evaluation and teaching OWASP API vulnerabilities. A global `vuln` flag (default: enabled) toggles between vulnerable and secure code paths. This audit covers both modes, noting which findings apply to each.

**Tech Stack:** Python 3, Flask 2.2.2, Connexion 2.14.2, SQLAlchemy 2.0.2, SQLite, JWT (PyJWT 2.6.0)

### Findings Overview

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH     | 4 |
| MEDIUM   | 4 |
| LOW      | 3 |
| INFO     | 2 |
| **Total** | **16** |

### Endpoints Audited

| Method | Path | Auth Required |
|--------|------|---------------|
| GET | `/` | No |
| GET | `/createdb` | No |
| GET | `/users/v1` | No |
| GET | `/users/v1/_debug` | No |
| GET | `/users/v1/{username}` | No |
| POST | `/users/v1/register` | No |
| POST | `/users/v1/login` | No |
| GET | `/me` | Yes |
| PUT | `/users/v1/{username}/email` | Yes |
| PUT | `/users/v1/{username}/password` | Yes |
| DELETE | `/users/v1/{username}` | Yes |
| GET | `/books/v1` | No |
| POST | `/books/v1` | Yes |
| GET | `/books/v1/{book_title}` | Yes |

---

## Findings

### CRITICAL

#### [C1] SQL Injection in User Lookup

**Category:** Additional — Injection Flaws
**Location:** `models/user_model.py:72-73`
**Affected Endpoint:** `GET /users/v1/{username}`
**Mode:** Vulnerable only (`vuln=1`)

**Description:**
The `get_user()` method constructs a SQL query using an f-string with unsanitized user input. An attacker can inject arbitrary SQL to extract data, modify records, or bypass authentication.

**Vulnerable Code:**
```python
# models/user_model.py:71-74
if vuln:  # SQLi Injection
    user_query = f"SELECT * FROM users WHERE username = '{username}'"
    query = db.session.execute(text(user_query))
```

**Attack Scenario:**
1. Attacker sends `GET /users/v1/' OR '1'='1' --`
2. The injected SQL bypasses the WHERE clause, returning all users
3. UNION-based injection can extract passwords: `GET /users/v1/' UNION SELECT 1,username,password,email,1 FROM users--`

**Remediation:**
```python
def get_user(username):
    user = User.query.filter_by(username=username).first()
    return user
```

---

#### [C2] Plaintext Password Storage

**Category:** API2:2023 — Broken Authentication
**Location:** `models/user_model.py:15`, `api_views/users.py:93`
**Affected Endpoint:** All auth endpoints
**Mode:** Both modes

**Description:**
Passwords are stored in plaintext in the database. The login function compares passwords directly with `==`. If the database is compromised (e.g., via the SQL injection above or the debug endpoint), all credentials are immediately usable.

**Vulnerable Code:**
```python
# models/user_model.py:15
password = db.Column(db.String(128), nullable=False)

# api_views/users.py:93 — plaintext comparison
if user and request_data.get('password') == user.password:
```

**Attack Scenario:**
1. Attacker accesses `/users/v1/_debug` to dump all user records
2. Passwords are returned in plaintext and can be used directly for login
3. Credential reuse across other services is immediately possible

**Remediation:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    def __init__(self, username, password, email, admin=False):
        self.username = username
        self.password = generate_password_hash(password)
        self.email = email
        self.admin = admin

# In login:
if user and check_password_hash(user.password, request_data.get('password')):
```

---

#### [C3] Unauthenticated Debug Endpoint Exposes All Credentials

**Category:** API3:2023 — Broken Object Property Level Authorization
**Location:** `api_views/users.py:24-26`, `models/user_model.py:58-59`
**Affected Endpoint:** `GET /users/v1/_debug`
**Mode:** Both modes (no vuln check)

**Description:**
The `/users/v1/_debug` endpoint returns all user records including plaintext passwords and admin status, with no authentication or authorization required. This endpoint has no `vuln` flag check — it is always accessible.

**Vulnerable Code:**
```python
# api_views/users.py:24-26
def debug():
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value

# models/user_model.py:58-59
def json_debug(self):
    return {'username': self.username, 'password': self.password, 'email': self.email, 'admin': self.admin}
```

**Attack Scenario:**
1. Attacker sends `GET /users/v1/_debug`
2. Receives all usernames, passwords, emails, and admin flags
3. Uses admin credentials to delete other users or access all books

**Remediation:**
Remove the endpoint entirely, or restrict it to authenticated admin users:
```python
def debug():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Unauthorized"), 403, mimetype="application/json")
    return jsonify({'users': User.get_all_users_debug()})
```

---

### HIGH

#### [H1] Unauthorized Password Change (BOLA)

**Category:** API1:2023 — Broken Object Level Authorization
**Location:** `api_views/users.py:186-191`
**Affected Endpoint:** `PUT /users/v1/{username}/password`
**Mode:** Vulnerable only (`vuln=1`)

**Description:**
When `vuln=1`, the password update endpoint uses the `username` path parameter instead of the authenticated user's identity. Any authenticated user can change any other user's password.

**Vulnerable Code:**
```python
# api_views/users.py:186-191
if vuln:  # Unauthorized update of password of another user
    user = User.query.filter_by(username=username).first()
    if user:
        user.password = request_data.get('password')
        db.session.commit()
```

**Attack Scenario:**
1. Attacker registers an account and obtains a JWT
2. Sends `PUT /users/v1/admin/password` with `{"password": "hacked"}`
3. Admin password is changed; attacker logs in as admin

**Remediation:**
```python
# Always use the authenticated user's identity
user = User.query.filter_by(username=resp['sub']).first()
user.password = request_data.get('password')
```

---

#### [H2] Broken Object Level Authorization on Books

**Category:** API1:2023 — Broken Object Level Authorization
**Location:** `api_views/books.py:50-58`
**Affected Endpoint:** `GET /books/v1/{book_title}`
**Mode:** Vulnerable only (`vuln=1`)

**Description:**
When `vuln=1`, any authenticated user can retrieve any book's secret content regardless of ownership. The query does not filter by the authenticated user.

**Vulnerable Code:**
```python
# api_views/books.py:50-58
if vuln:  # Broken Object Level Authorization
    book = Book.query.filter_by(book_title=str(book_title)).first()
    if book:
        responseObject = {
            'book_title': book.book_title,
            'secret': book.secret_content,
            'owner': book.user.username
        }
```

**Attack Scenario:**
1. Attacker authenticates with any valid account
2. Browses `/books/v1` to see all book titles
3. Requests `GET /books/v1/{any_title}` to read another user's secret content

**Remediation:**
```python
user = User.query.filter_by(username=resp['sub']).first()
book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
```

---

#### [H3] Mass Assignment — Admin Privilege Escalation

**Category:** API3:2023 — Broken Object Property Level Authorization
**Location:** `api_views/users.py:60-66`
**Affected Endpoint:** `POST /users/v1/register`
**Mode:** Vulnerable only (`vuln=1`)

**Description:**
When `vuln=1`, the registration endpoint accepts an `admin` field in the request body, allowing any user to register as an admin. The `admin` field is not part of the documented schema.

**Vulnerable Code:**
```python
# api_views/users.py:60-66
if vuln and 'admin' in request_data:
    if request_data['admin']:
        admin = True
    else:
        admin = False
    user = User(username=request_data['username'], password=request_data['password'],
                email=request_data['email'], admin=admin)
```

**Attack Scenario:**
1. Attacker sends `POST /users/v1/register` with `{"username": "evil", "password": "pass", "email": "e@e.com", "admin": true}`
2. Account is created with admin privileges
3. Attacker can now delete other users via `DELETE /users/v1/{username}`

**Remediation:**
```python
# Never accept admin field from user input
user = User(username=request_data['username'], password=request_data['password'],
            email=request_data['email'])
```

---

#### [H4] Weak JWT Secret Key

**Category:** API2:2023 — Broken Authentication
**Location:** `config.py:13`
**Affected Endpoint:** All authenticated endpoints
**Mode:** Both modes

**Description:**
The JWT signing secret is hardcoded as the string `'random'`. This can be trivially brute-forced or guessed, allowing an attacker to forge valid JWT tokens for any user including admins.

**Vulnerable Code:**
```python
# config.py:13
vuln_app.app.config['SECRET_KEY'] = 'random'
```

**Attack Scenario:**
1. Attacker obtains a valid JWT from `/users/v1/login`
2. Decodes the JWT (base64) and sees the HS256 algorithm
3. Brute-forces the secret (dictionary attack on common words finds `'random'` instantly)
4. Forges a token with `"sub": "admin"` to gain admin access

**Remediation:**
```python
import os
vuln_app.app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
```

---

### MEDIUM

#### [M1] User and Password Enumeration

**Category:** API2:2023 — Broken Authentication
**Location:** `api_views/users.py:101-106`
**Affected Endpoint:** `POST /users/v1/login`
**Mode:** Vulnerable only (`vuln=1`)

**Description:**
When `vuln=1`, the login endpoint returns different error messages for "user not found" vs. "wrong password", allowing attackers to enumerate valid usernames.

**Vulnerable Code:**
```python
# api_views/users.py:101-106
if vuln:  # Password Enumeration
    if user and request_data.get('password') != user.password:
        return Response(error_message_helper("Password is not correct for the given username."), ...)
    elif not user:  # User enumeration
        return Response(error_message_helper("Username does not exist"), ...)
```

**Attack Scenario:**
1. Attacker submits login with `{"username": "admin", "password": "wrong"}`
2. Response: "Password is not correct" — confirms `admin` is a valid username
3. Attacker submits `{"username": "nonexistent", "password": "x"}`
4. Response: "Username does not exist" — confirms username is invalid
5. Attacker builds a list of valid usernames, then brute-forces passwords

**Remediation:**
```python
# Use generic message for both cases (already implemented in secure mode)
return Response(error_message_helper("Username or Password Incorrect!"), ...)
```

---

#### [M2] ReDoS in Email Validation

**Category:** API4:2023 — Unrestricted Resource Consumption
**Location:** `api_views/users.py:144-146`
**Affected Endpoint:** `PUT /users/v1/{username}/email`
**Mode:** Vulnerable only (`vuln=1`)

**Description:**
The email validation regex contains nested quantifiers `([-.\w]*[0-9a-zA-Z])*` that can cause catastrophic backtracking with crafted input, leading to denial of service.

**Vulnerable Code:**
```python
# api_views/users.py:144-146
match = re.search(
    r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
    str(request_data.get('email')))
```

**Attack Scenario:**
1. Attacker authenticates and sends `PUT /users/v1/name1/email` with `{"email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}`
2. The regex engine enters catastrophic backtracking, consuming CPU for seconds to minutes
3. Repeated requests can cause application-wide denial of service

**Remediation:**
Use a simple, non-backtracking regex or a dedicated email validation library:
```python
import re
regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
```

---

#### [M3] Unauthenticated Database Reset Endpoint

**Category:** API5:2023 — Broken Function Level Authorization
**Location:** `api_views/main.py:6-12`
**Affected Endpoint:** `GET /createdb`
**Mode:** Both modes

**Description:**
The `/createdb` endpoint drops all tables and recreates the database with seed data. It requires no authentication, allowing anyone to wipe all application data.

**Vulnerable Code:**
```python
# api_views/main.py:6-9
def populate_db():
    db.drop_all()
    db.create_all()
    User.init_db_users()
```

**Attack Scenario:**
1. Attacker sends `GET /createdb`
2. All user data, books, and custom accounts are destroyed
3. Database is reset to seed data only

**Remediation:**
Restrict to admin users or remove from production:
```python
def populate_db():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Admin only"), 403, mimetype="application/json")
    db.drop_all()
    db.create_all()
    User.init_db_users()
```

---

#### [M4] No Rate Limiting on Any Endpoint

**Category:** API4:2023 — Unrestricted Resource Consumption
**Location:** Application-wide
**Affected Endpoint:** All endpoints, especially `POST /users/v1/login`
**Mode:** Both modes

**Description:**
No rate limiting is implemented on any endpoint. The login endpoint is particularly vulnerable to brute-force attacks, and the registration endpoint to automated account creation.

**Attack Scenario:**
1. Attacker scripts unlimited login attempts to brute-force passwords
2. Given the weak password policy (no minimum complexity), credentials can be guessed quickly
3. Mass account registration is also unrestricted

**Remediation:**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app=vuln_app.app, key_func=get_remote_address)

# Apply to login endpoint
@limiter.limit("5/minute")
def login_user():
    ...
```

---

### LOW

#### [L1] Debug Mode Enabled in Production

**Category:** API8:2023 — Security Misconfiguration
**Location:** `app.py:17`
**Affected Endpoint:** N/A (server configuration)
**Mode:** Both modes

**Description:**
Flask's debug mode is enabled (`debug=True`), which enables the Werkzeug interactive debugger. In production, this allows remote code execution if the debugger PIN is bypassed.

**Vulnerable Code:**
```python
# app.py:17
vuln_app.run(host='0.0.0.0', port=5000, debug=True)
```

**Attack Scenario:**
1. An unhandled exception triggers the Werkzeug debugger in the browser
2. Attacker accesses the interactive console
3. If the debugger PIN is guessed/leaked, attacker achieves remote code execution

**Remediation:**
```python
vuln_app.run(host='0.0.0.0', port=5000, debug=False)
```

---

#### [L2] No Password Complexity Requirements

**Category:** API2:2023 — Broken Authentication
**Location:** `api_views/json_schemas.py:1-9`
**Affected Endpoint:** `POST /users/v1/register`, `PUT /users/v1/{username}/password`
**Mode:** Both modes

**Description:**
The registration schema accepts any string as a password with no minimum length, complexity, or entropy requirements. The password update endpoint performs no validation at all.

**Vulnerable Code:**
```python
# api_views/json_schemas.py:4
"password": {"type": "string"},
```

**Attack Scenario:**
1. Users register with single-character passwords like `"a"`
2. Combined with no rate limiting, brute-force attacks are trivially fast

**Remediation:**
```python
"password": {"type": "string", "minLength": 8, "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$"},
```

---

#### [L3] Bare Except Clauses Suppress Errors

**Category:** API8:2023 — Security Misconfiguration
**Location:** `api_views/users.py:113`, `api_views/users.py:136`, `api_views/books.py:21`
**Affected Endpoint:** Multiple
**Mode:** Both modes

**Description:**
Multiple bare `except:` clauses catch all exceptions, including `SystemExit` and `KeyboardInterrupt`, and return generic error messages. This can mask security-relevant errors and make debugging difficult.

**Vulnerable Code:**
```python
# api_views/users.py:113
except:
    return Response(error_message_helper("An error occurred!"), 200, mimetype="application/json")

# api_views/users.py:136
except:
    return Response(error_message_helper("Please provide a proper JSON body."), 400, ...)
```

**Remediation:**
```python
except Exception as e:
    logging.error(f"Login error: {e}")
    return Response(error_message_helper("An error occurred!"), 500, mimetype="application/json")
```

---

### INFO

#### [I1] No CORS Configuration

**Category:** API8:2023 — Security Misconfiguration
**Location:** Application-wide
**Affected Endpoint:** All endpoints
**Mode:** Both modes

**Description:**
No CORS policy is configured. While this defaults to same-origin (blocking cross-origin requests from browsers), there is no explicit CORS configuration to control which origins can access the API. If CORS is later added permissively, it could expose the API to cross-site attacks.

**Remediation:**
Add explicit CORS configuration with allowed origins:
```python
from flask_cors import CORS
CORS(vuln_app.app, origins=["https://trusted-domain.com"])
```

---

#### [I2] No Logging or Audit Trail

**Category:** Additional — Logging & Monitoring
**Location:** Application-wide
**Affected Endpoint:** All endpoints
**Mode:** Both modes

**Description:**
The application has no logging of authentication attempts, authorization failures, or data access. Security incidents would be undetectable without external monitoring.

**Remediation:**
Add structured logging for security events:
```python
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In login_user():
logger.info(f"Login attempt for user: {request_data.get('username')}")
logger.warning(f"Failed login for user: {request_data.get('username')}")
```

---

## Remediation Priority

1. **[C1] Fix SQL Injection** — Use parameterized queries in `get_user()` to prevent data exfiltration
2. **[C3] Remove or restrict debug endpoint** — `/users/v1/_debug` exposes all credentials without authentication
3. **[C2] Hash passwords** — Use bcrypt/argon2 to store password hashes instead of plaintext
4. **[H4] Use a strong JWT secret** — Replace `'random'` with a cryptographically random key from environment
5. **[H1] Fix password update authorization** — Always use the authenticated user's identity, not the path parameter
6. **[H2] Fix book access authorization** — Filter books by the authenticated user's ownership
7. **[H3] Remove mass assignment** — Never accept the `admin` field from user registration input
8. **[M3] Protect database reset** — Require admin authentication for `/createdb`
9. **[M4] Add rate limiting** — Especially on login and registration endpoints
10. **[M1] Use generic auth error messages** — Prevent user/password enumeration
11. **[M2] Fix ReDoS regex** — Replace with a safe email validation pattern
12. **[L1] Disable debug mode** — Never run with `debug=True` in production

## Methodology

This audit was conducted using static analysis of the source code, following the OWASP API Security Top 10 (2023) framework. The following areas were examined:

- Authentication and authorization mechanisms
- Input validation and data handling
- Configuration and deployment security
- Dependency security
- API endpoint inventory and access controls
