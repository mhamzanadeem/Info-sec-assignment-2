"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

def now_ms(): raise NotImplementedError

def b64e(b: bytes): raise NotImplementedError

def b64d(s: str): raise NotImplementedError

def sha256_hex(data: bytes): raise NotImplementedError
