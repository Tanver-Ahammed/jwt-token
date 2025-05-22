# Getting Started

### Reference Documentation

In this project, I created a Simple JWT token,
verify the jwt token and get the public key for verifying the token.
It's a raw implementation of JWT token(without using any library).

### Project Structure

1. For getting the jwt token

```bash
curl "http://localhost:8080/jwt/generate?subject=Aminul-Bari"
```

2. For verifying the jwt token

```bash
curl -X POST "http://localhost:8080/jwt/validate" \
     -H "Content-Type: text/plain" \
     -d "<PASTE_JWT_TOKEN>"
```

3. For getting the public key

```bash
curl "http://localhost:8080/jwt/public-key"
```
