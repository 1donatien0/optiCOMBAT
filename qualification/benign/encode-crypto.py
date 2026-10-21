import hashlib

def digest(text):
    data = text.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

key = self.crypto.random_bytes(16)
print("saved as report.encrypted")
