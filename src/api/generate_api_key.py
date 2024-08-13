import secrets
import hashlib

def generate_api_key():
        return secrets.token_urlsafe(32)

def hash_secret(api_key):
        return hashlib.sha256(api_key.encode()).hexdigest()

# example
api_key = generate_api_key() # give to user
hashed_api_key = hash_secret(api_key) # store for authentication

print(f"Secret key: {api_key}")
print(f"Hash of key: {hashed_api_key}")
