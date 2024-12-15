from __future__ import annotations

import base64
import threading
from abc import ABC, abstractmethod
from typing import Optional

from cryptography import exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class PrivateKey(ABC):
    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        ...

    @abstractmethod
    def get_public_key(self) -> PublicKey:
        ...


class PublicKey(ABC):
    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        ...

    @abstractmethod
    def to_bytes(self) -> bytes:
        ...

    @classmethod
    @abstractmethod
    def from_bytes(cls, key: bytes) -> bytes:
        ...

class Ed25519PrivateKey(PrivateKey):
    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        if private_key is None:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            self._private_key = private_key

    _process_wide_key = None
    _process_wide_key_lock = threading.RLock()

    @classmethod
    def process_wide(cls) -> Ed25519PrivateKey:
        print("crypto.py Ed25519PrivateKey process_wide")
        if cls._process_wide_key is None:
            with cls._process_wide_key_lock:
                if cls._process_wide_key is None:
                    cls._process_wide_key = cls()
        return cls._process_wide_key

    def sign(self, data: bytes) -> bytes:
        print("crypto.py Ed25519PrivateKey sign")
        signature = self._private_key.sign(data)
        return base64.b64encode(signature)

    def get_public_key(self) -> Ed25519PublicKey:
        print("crypto.py Ed25519PrivateKey get_public_key")
        return Ed25519PublicKey(self._private_key.public_key())

    def to_bytes(self) -> bytes:
        print("crypto.py Ed25519PrivateKey to_bytes")
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def __getstate__(self):
        print("crypto.py Ed25519PrivateKey __getstate__")
        state = self.__dict__.copy()
        # Serializes the private key to make the class instances picklable
        state["_private_key"] = self.to_bytes()
        return state

    def __setstate__(self, state):
        print("crypto.py Ed25519PrivateKey __setstate__")
        self.__dict__.update(state)
        # self._private_key = serialization.load_der_private_key(self._private_key, password=None)
        # self._private_key = serialization.load_pem_private_key(self._private_key, password=None)
        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(self._private_key)


class Ed25519PublicKey(PublicKey):
    def __init__(self, public_key: ed25519.Ed25519PublicKey):
        self._public_key = public_key

    def verify(self, data: bytes, signature: bytes) -> bool:
        print("crypto.py Ed25519PublicKey verify")
        try:
            signature = base64.b64decode(signature)

            # Returns None if the signature is correct, raises an exception otherwise
            self._public_key.verify(signature, data)

            return True
        except (ValueError, exceptions.InvalidSignature):
            return False

    def to_bytes(self) -> bytes:
        print("crypto.py Ed25519PublicKey to_bytes")
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
        )

    def to_raw_bytes(self) -> bytes:
        print("crypto.py Ed25519PublicKey to_raw_bytes")
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    @classmethod
    def from_bytes(cls, key: bytes) -> Ed25519PublicKey:
        print("crypto.py Ed25519PublicKey from_bytes")
        key = serialization.load_ssh_public_key(key)
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError(f"Expected an Ed25519 public key, got {key}")
        return cls(key)
