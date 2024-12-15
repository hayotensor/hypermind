import base64
from datetime import datetime, timedelta
import hashlib
import os
import secrets
from typing import Optional

import multihash
import pytest

from hivemind.proto import dht_pb2
from hivemind.proto.auth_pb2 import AccessToken
from hivemind.dht.routing import DHTID
from hivemind.p2p.p2p_daemon import P2P
from hivemind.p2p.p2p_daemon_bindings.datastructures import PeerID
from hivemind.utils.auth import AuthRole, AuthRPCWrapper, AuthorizedRequestBase, AuthorizedResponseBase, AuthorizerBase, TokenAuthorizerBase
from hivemind.utils.crypto import Ed25519PrivateKey, Ed25519PublicKey
from hivemind.utils.logging import get_logger
from cryptography.hazmat.primitives import serialization
from hivemind.proto import crypto_pb2, p2pd_pb2
from cryptography.hazmat.primitives.asymmetric import ed25519
from hivemind.utils.timed_storage import TimedStorage, get_dht_time

logger = get_logger(__name__)

# pytest tests/ed25519 -rP

# pytest tests/ed25519/test_auth.py -rP

class MockAuthorizer(TokenAuthorizerBase):
    _authority_private_key = None
    _authority_public_key = None

    def __init__(self, local_private_key: Optional[Ed25519PrivateKey], username: str = "mock"):
        super().__init__(local_private_key)

        self._username = username
        self._authority_public_key = None

    async def get_token(self) -> AccessToken:
        if MockAuthorizer._authority_private_key is None:
            MockAuthorizer._authority_private_key = Ed25519PrivateKey()

        self._authority_public_key = MockAuthorizer._authority_private_key.get_public_key()

        token = AccessToken(
            username=self._username,
            public_key=self.local_public_key.to_bytes(),
            expiration_time=str(datetime.utcnow() + timedelta(minutes=1)),
        )
        token.signature = MockAuthorizer._authority_private_key.sign(self._token_to_bytes(token))
        return token

    def is_token_valid(self, access_token: AccessToken) -> bool:
        data = self._token_to_bytes(access_token)
        if not self._authority_public_key.verify(data, access_token.signature):
            logger.exception("Access token has invalid signature")
            return False

        try:
            expiration_time = datetime.fromisoformat(access_token.expiration_time)
        except ValueError:
            logger.exception(
                f"datetime.fromisoformat() failed to parse expiration time: {access_token.expiration_time}"
            )
            return False
        if expiration_time.tzinfo is not None:
            logger.exception(f"Expected to have no timezone for expiration time: {access_token.expiration_time}")
            return False
        if expiration_time < datetime.utcnow():
            logger.exception("Access token has expired")
            return False

        return True

    _MAX_LATENCY = timedelta(minutes=1)

    def does_token_need_refreshing(self, access_token: AccessToken) -> bool:
        expiration_time = datetime.fromisoformat(access_token.expiration_time)
        return expiration_time < datetime.utcnow() + self._MAX_LATENCY

    @staticmethod
    def _token_to_bytes(access_token: AccessToken) -> bytes:
        return f"{access_token.username} {access_token.public_key} {access_token.expiration_time}".encode()

class MockAuthorizer2(AuthorizerBase):
    def __init__(self, local_private_key: Ed25519PrivateKey):
        super().__init__()

        self._local_private_key = local_private_key
        self._local_public_key = local_private_key.get_public_key()

    async def get_token(self) -> AccessToken:
        token = AccessToken(
            username='',
            public_key=self._local_public_key.to_bytes(),
            expiration_time=str(datetime.utcnow() + timedelta(minutes=1)),
        )
        token.signature = self._local_private_key.sign(self._token_to_bytes(token))
        return token

    @staticmethod
    def _token_to_bytes(access_token: AccessToken) -> bytes:
        return f"{access_token.username} {access_token.public_key} {access_token.expiration_time}".encode()

    async def sign_request(self, request: AuthorizedRequestBase, service_public_key: Optional[Ed25519PublicKey]) -> None:
        print("sign_request request: ", request)
        auth = request.auth

        # auth.client_access_token.CopyFrom(self._local_access_token)
        local_access_token = await self.get_token()
        auth.client_access_token.CopyFrom(local_access_token)

        if service_public_key is not None:
            auth.service_public_key = service_public_key.to_bytes()
        auth.time = get_dht_time()
        auth.nonce = secrets.token_bytes(8)

        assert auth.signature == b""
        auth.signature = self._local_private_key.sign(request.SerializeToString())

    _MAX_CLIENT_SERVICER_TIME_DIFF = timedelta(minutes=1)

    async def validate_request(self, request: AuthorizedRequestBase) -> bool:
        print("validate_request request: ", request)
        auth = request.auth
        print("validate_request auth: ", auth)

        # Get public key of signer
        try:
            client_public_key = Ed25519PublicKey.from_bytes(auth.client_access_token.public_key)
        except:
            return False

        print("validate_request client_public_key", client_public_key)
        print("validate_request client_public_key to_bytes", client_public_key.to_bytes())
        print("validate_request client_public_key to_raw_bytes", client_public_key.to_raw_bytes())

        signature = auth.signature
        print("validate_request signature", signature)
        auth.signature = b""
        # Verify signature of the request from signer
        if not client_public_key.verify(request.SerializeToString(), signature):
            logger.debug("Request has invalid signature")
            return False

        if auth.service_public_key and auth.service_public_key != self._local_public_key.to_bytes():
            logger.debug("Request is generated for a peer with another public key")
            return False

        try:
            encoded_public_key = crypto_pb2.PublicKey(
                key_type=crypto_pb2.Ed25519,
                data=client_public_key.to_raw_bytes(),
            ).SerializeToString()

            encoded_public_key = b"\x00$" + encoded_public_key

            peer_id = PeerID(encoded_public_key)
        except:
            return False

        return True

    async def sign_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> None:
        print("sign_response response: ", response)
        print("sign_response request: ", request)

        auth = response.auth
        print("sign_response auth: ", auth)
        print("sign_response auth.signature: ", auth.signature)

        local_access_token = await self.get_token()
        auth.service_access_token.CopyFrom(local_access_token)

        # auth.service_access_token.CopyFrom(self._local_public_key)
        auth.nonce = request.auth.nonce

        assert auth.signature == b""
        auth.signature = self._local_private_key.sign(response.SerializeToString())

    async def validate_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> bool:
        print("validate_response response: ", response)
        print("validate_response request: ", request)
        auth = response.auth
        
        service_public_key = Ed25519PublicKey.from_bytes(auth.service_access_token.public_key)
        signature = auth.signature
        auth.signature = b""
        if not service_public_key.verify(response.SerializeToString(), signature):
            logger.debug("Response has invalid signature")
            return False

        if auth.nonce != request.auth.nonce:
            logger.debug("Response is generated for another request")
            return False

        return True

    @property
    def local_public_key(self) -> Ed25519PublicKey:
        return self._local_public_key

# pytest tests/ed25519/test_auth.py::test_write_ed25519_peer_id_pem_generated -rP

@pytest.mark.asyncio
async def test_write_ed25519_peer_id_pem_generated():
    # test writing
#     private_key = b"""-----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
# -----END PRIVATE KEY-----"""

#     protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=private_key)

    # with open('tests/ed25519/private_key_pem.key', "wb") as f:
    #     f.write(protobuf.SerializeToString())

    with open('tests/ed25519/private_key_pem.key', "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])

        encoded_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)
        print("test_write_ed25519_peer_id encoded_public_key here2:\n", len(encoded_public_key))

        combined_key_bytes = private_key.private_bytes_raw() + encoded_public_key

        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.Ed25519,
            data=combined_key_bytes,
        ).SerializeToString()
        print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)
        print("encoded_public_key pem len:\n", len(encoded_public_key))

        encoded_digest = multihash.encode(
            hashlib.sha256(encoded_public_key).digest(),
            multihash.coerce_code("sha2-256"),
        )
        print("test_write_ed25519_peer_id encoded_digest:\n", encoded_digest)

        print("test_write_ed25519_peer_id encoded_digest", PeerID(encoded_digest))


    p2p = await P2P.create(identity_path='tests/ed25519/private_key_generated.key')

    p2p_peer_id = p2p.peer_id

    print("test_write_ed25519_peer_id p2p_peer_id", p2p_peer_id)

    await p2p.shutdown()

# pytest tests/ed25519/test_auth.py::test_write_ed25519_peer_id_pem -rP

@pytest.mark.asyncio
async def test_write_ed25519_peer_id_pem():
    # test writing
    private_key = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
-----END PRIVATE KEY-----"""

    # private_key = ed25519.Ed25519PrivateKey.generate()

    # private_key = private_key.private_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.PKCS8,  # Standard format for private keys
    #     encryption_algorithm=serialization.NoEncryption()  # No password protection
    # )

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=private_key)

    print("test_write_ed25519_peer_id protobuf.SerializeToString():\n", protobuf.SerializeToString())

    with open('tests/ed25519/private_key_pem.key', "wb") as f:
        f.write(protobuf.SerializeToString())

    with open('tests/ed25519/private_key_pem.key', "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        print("test_write_ed25519_peer_id key_data:\n", key_data)

        private_key = serialization.load_pem_private_key(key_data, password=None)
        print("test_write_ed25519_peer_id private_key:\n", private_key)

        encoded_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)
        print("test_write_ed25519_peer_id encoded_public_key here2:\n", len(encoded_public_key))

        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.Ed25519,
            data=encoded_public_key,
        ).SerializeToString()
        print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)
        print("encoded_public_key pem len:\n", len(encoded_public_key))

        encoded_digest = multihash.encode(
            hashlib.sha256(encoded_public_key).digest(),
            multihash.coerce_code("sha2-256"),
        )
        print("test_write_ed25519_peer_id encoded_digest:\n", encoded_digest)

        print("test_write_ed25519_peer_id encoded_digest", PeerID(encoded_digest))


    p2p = await P2P.create(identity_path='tests/ed25519/private_key_pem.key')

    p2p_peer_id = p2p.peer_id

    print("test_write_ed25519_peer_id p2p_peer_id", p2p_peer_id)

    await p2p.shutdown()

# pytest tests/ed25519/test_auth.py::test_write_ed25519_combined_peer_id_pem -rP

# @pytest.mark.asyncio
# async def test_write_ed25519_combined_peer_id_pem():
#     # test writing
#     private_key = b"""-----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
# -----END PRIVATE KEY-----"""

#     # private_key = ed25519.Ed25519PrivateKey.generate()

#     # private_key = private_key.private_bytes(
#     #     encoding=serialization.Encoding.PEM,
#     #     format=serialization.PrivateFormat.PKCS8,  # Standard format for private keys
#     #     encryption_algorithm=serialization.NoEncryption()  # No password protection
#     # )
#     pem_private_key = serialization.load_pem_private_key(private_key, password=None)

#     raw_private_key = pem_private_key.private_bytes(
#         encoding=serialization.Encoding.Raw,  # DER format
#         format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
#         encryption_algorithm=serialization.NoEncryption()  # No encryption
#     )

#     raw_public_key = pem_private_key.public_key().public_bytes(
#         encoding=serialization.Encoding.Raw,
#         format=serialization.PublicFormat.Raw,
#     )

#     combined_key_bytes = raw_private_key + raw_public_key
#     protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

#     # protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=private_key)

#     with open('tests/ed25519/private_key_pem.key', "wb") as f:
#         f.write(protobuf.SerializeToString())

#     with open('tests/ed25519/private_key_pem.key', "rb") as f:
#         data = f.read()
#         key_data = crypto_pb2.PrivateKey.FromString(data).data
#         print("test_write_ed25519_combined_peer_id_pem key_data:\n", key_data)

#         private_key = serialization.load_pem_private_key(key_data, password=None)
#         print("test_write_ed25519_combined_peer_id_pem private_key:\n", private_key)

#         private_key_bytes = private_key.private_bytes(
#             encoding=serialization.Encoding.Raw,  # No encoding for raw bytes
#             format=serialization.PrivateFormat.Raw,    # No specific format for raw bytes
#             encryption_algorithm=serialization.NoEncryption()
#         )

#         print("test_write_ed25519_peer_id private_key_bytes:\n", private_key_bytes)
#         print("test_write_ed25519_peer_id private_key_bytes:\n", len(private_key_bytes))

#         public_key_bytes = private_key.public_key().public_bytes(
#             encoding=serialization.Encoding.Raw,
#             format=serialization.PublicFormat.Raw,
#         )
#         print("test_write_ed25519_peer_id public_key_bytes:\n", public_key_bytes)
#         print("test_write_ed25519_peer_id public_key_bytes:\n", len(public_key_bytes))

#         combined_key_bytes = private_key_bytes + public_key_bytes
#         print("test_write_ed25519_peer_id combined_key_bytes:\n", combined_key_bytes)
#         print("test_write_ed25519_peer_id combined_key_bytes:\n", len(combined_key_bytes))

#         encoded_public_key = crypto_pb2.PublicKey(
#             key_type=crypto_pb2.Ed25519,
#             data=combined_key_bytes,
#         ).SerializeToString()
#         print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)
#         print("encoded_public_key pem len:\n", len(encoded_public_key))

#         encoded_digest = multihash.encode(
#             hashlib.sha256(encoded_public_key).digest(),
#             multihash.coerce_code("sha2-256"),
#         )
#         print("test_write_ed25519_peer_id encoded_digest:\n", encoded_digest)


#         peer_id = PeerID(encoded_digest)
#         print("test_write_ed25519_peer_id peer_id", peer_id)

#         peer_id_to_bytes = peer_id.to_bytes()

#         assert encoded_digest == peer_id_to_bytes


#     p2p = await P2P.create(identity_path='private_key_pem.key')

#     p2p_peer_id = p2p.peer_id

#     print("test_write_ed25519_peer_id p2p_peer_id", p2p_peer_id)

#     await p2p.shutdown()

# @pytest.mark.asyncio
# async def test_write_ed25519_peer_id_der():
#     # test writing
#     private_key = b"""-----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
# -----END PRIVATE KEY-----"""

#     private_key = serialization.load_pem_private_key(
#         private_key,  # Convert string to bytes
#         password=None  # Provide the password if the key is encrypted
#     )

#     private_key = private_key.private_bytes(
#         encoding=serialization.Encoding.DER,  # DER format
#         format=serialization.PrivateFormat.PKCS8,  # PKCS8 standard format
#         encryption_algorithm=serialization.NoEncryption()  # No encryption
#     )

#     protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=private_key)
#     print("test_write_ed25519_peer_id protobuf:\n", protobuf)

#     print("test_write_ed25519_peer_id protobuf.SerializeToString():\n", protobuf.SerializeToString())

#     with open('tests/ed25519/private_key_2.pem', "wb") as f:
#         f.write(protobuf.SerializeToString())

#     with open('tests/ed25519/private_key_2.pem', "rb") as f:
#         data = f.read()
#         key_data = crypto_pb2.PrivateKey.FromString(data).data
#         print("test_write_ed25519_peer_id key_data:\n", key_data)

#         private_key = serialization.load_der_private_key(key_data, password=None)
#         print("test_write_ed25519_peer_id private_key:\n", private_key)

#         encoded_public_key = private_key.public_key().public_bytes(
#             encoding=serialization.Encoding.DER,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo,
#         )
#         print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)

#         encoded_public_key = crypto_pb2.PublicKey(
#             key_type=crypto_pb2.Ed25519,
#             data=encoded_public_key,
#         ).SerializeToString()
#         print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)
#         print("encoded_public_key  dem len:\n", len(encoded_public_key))

#         encoded_digest = multihash.encode(
#             hashlib.sha256(encoded_public_key).digest(),
#             multihash.coerce_code("sha2-256"),
#         )
#         print("test_write_ed25519_peer_id encoded_digest:\n", encoded_digest)

#         print("test_write_ed25519_peer_id encoded_digest", PeerID(encoded_digest))


#     p2p = await P2P.create(identity_path='tests/ed25519/private_key_2.pem')

#     p2p_peer_id = p2p.peer_id

#     print("test_write_ed25519_peer_id p2p_peer_id", p2p_peer_id)

#     await p2p.shutdown()

# pytest tests/ed25519/test_auth.py::test_write_ed25519_combined_peer_id_raw -rP

@pytest.mark.asyncio
async def test_write_ed25519_combined_peer_id_raw():
    # test writing
    private_key = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
-----END PRIVATE KEY-----"""

    pem_private_key = serialization.load_pem_private_key(private_key, password=None)
    print("test_write_ed25519_combined_peer_id_raw pem_private_key:\n", pem_private_key)

    pem_private_key_raw = pem_private_key.private_bytes_raw()
    print("test_write_ed25519_combined_peer_id_raw pem_private_key_raw:\n", pem_private_key_raw)
    print("test_write_ed25519_combined_peer_id_raw pem_private_key_raw:\n", len(pem_private_key_raw))

    raw_private_key = pem_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,  # DER format
        format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
        encryption_algorithm=serialization.NoEncryption()  # No encryption
    )

    raw_public_key = pem_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    combined_key_bytes = raw_private_key + raw_public_key
    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

    with open('tests/ed25519/private_key_raw_pem.key', "wb") as f:
        f.write(protobuf.SerializeToString())

    with open('tests/ed25519/private_key_raw_pem.key', "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])

        assert raw_private_key == private_key.private_bytes_raw()

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        print("test_write_ed25519_combined_peer_id_raw public_key_bytes:\n", public_key_bytes)
        print("test_write_ed25519_combined_peer_id_raw public_key_bytes:\n", len(public_key_bytes))

        assert raw_public_key == public_key_bytes

        combined_key_bytes = private_key.private_bytes_raw() + public_key_bytes

        # combined_key_bytes_peer_id = PeerID(combined_key_bytes)
        # print("test_write_ed25519_combined_peer_id_raw combined_key_bytes_peer_id", combined_key_bytes_peer_id)

        # encoded_test = multihash.encode(
        #     hashlib.sha256(combined_key_bytes).digest(),
        #     multihash.coerce_code("sha2-256"),
        # )
        # test_peer_id = PeerID(encoded_test)
        # print("test_write_ed25519_combined_peer_id_raw test_peer_id", test_peer_id)

        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.Ed25519,
            data=combined_key_bytes,
        ).SerializeToString()

        # test_peer_id2 = PeerID(encoded_public_key)
        # print("test_write_ed25519_combined_peer_id_raw test_peer_id2", test_peer_id2)

        encoded_digest = multihash.encode(
            hashlib.sha256(encoded_public_key).digest(),
            multihash.coerce_code("sha2-256"),
        )

        peer_id = PeerID(encoded_digest)
        print("test_write_ed25519_combined_peer_id_raw peer_id", peer_id)

        peer_id_to_bytes = peer_id.to_bytes()

        assert encoded_digest == peer_id_to_bytes


    p2p = await P2P.create(identity_path='tests/ed25519/private_key_raw_pem.key')

    p2p_peer_id = p2p.peer_id

    print("test_write_ed25519_combined_peer_id_raw p2p_peer_id", p2p_peer_id)
    print("test_write_ed25519_combined_peer_id_raw p2p_peer_id", p2p_peer_id.to_base58())


    await p2p.shutdown()

# pytest tests/ed25519/test_auth.py::test_write_ed25519_combined_peer_id_raw2 -rP

@pytest.mark.asyncio
async def test_write_ed25519_combined_peer_id_raw2():
    # test writing
    private_key = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
-----END PRIVATE KEY-----"""

    pem_private_key = serialization.load_pem_private_key(private_key, password=None)

    # encoded_public_key = pem_private_key.public_key().public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo,
    # )

    # encoded_public_key = crypto_pb2.PublicKey(
    #     key_type=crypto_pb2.Ed25519,
    #     data=encoded_public_key,
    # ).SerializeToString()

    # encoded_digest = multihash.encode(
    #     hashlib.sha256(encoded_public_key).digest(),
    #     multihash.coerce_code("sha2-256"),
    # )

    # print("test_write_ed25519_combined_peer_id_raw2 1111111: >", PeerID(encoded_digest))

    raw_private_key = pem_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,  # DER format
        format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
        encryption_algorithm=serialization.NoEncryption()  # No encryption
    )

    raw_public_key = pem_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print("test_write_ed25519_combined_peer_id_raw2 raw_public_key", raw_public_key)

    peer_id_raw_public_key = PeerID(raw_public_key)
    print("test_write_ed25519_combined_peer_id_raw2 peer_id_raw_public_key", peer_id_raw_public_key)
    encoded_public_key_raw_public_key = crypto_pb2.PublicKey(
        key_type=crypto_pb2.Ed25519,
        data=raw_public_key,
    ).SerializeToString()
    print("test_write_ed25519_combined_peer_id_raw2 encoded_public_key_raw_public_key:\n", encoded_public_key_raw_public_key)
    encoded_peer_id_raw_public_key = PeerID(encoded_public_key_raw_public_key)
    print("test_write_ed25519_combined_peer_id_raw2 encoded_peer_id_raw_public_key:\n", encoded_peer_id_raw_public_key)

    encoded_digest_raw_public_key = multihash.encode(
        hashlib.sha256(encoded_public_key_raw_public_key).digest(),
        multihash.coerce_code("sha2-256"),
    )
    print("test_write_ed25519_combined_peer_id_raw2 encoded_digest_raw_public_key", encoded_digest_raw_public_key)

    encoded_peer_id_raw_public_key2 = PeerID(encoded_digest_raw_public_key)
    print("test_write_ed25519_combined_peer_id_raw2 encoded_peer_id_raw_public_key2:\n", encoded_peer_id_raw_public_key2)

    combined_key_bytes = (raw_private_key + raw_public_key)
    # combined_key_bytes = raw_private_key
    print("test_write_ed25519_combined_peer_id_raw2 combined_key_bytes:\n", combined_key_bytes)
    print("test_write_ed25519_combined_peer_id_raw2 combined_key_bytes:\n", len(combined_key_bytes))
    # combined_key_bytes_base_64 = base64.b64encode(combined_key_bytes)
    # print("test_write_ed25519_combined_peer_id_raw2 combined_key_bytes_base_64:\n", combined_key_bytes_base_64)
    # print("test_write_ed25519_combined_peer_id_raw2 combined_key_bytes_base_64:\n", len(combined_key_bytes_base_64))

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

    with open('tests/ed25519/private_key_raw_pem2.key', "wb") as f:
        f.write(protobuf.SerializeToString())

    with open('tests/ed25519/private_key_raw_pem2.key', "rb") as f:
        data = f.read()
        # key_data = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519).FromString(data).data
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        print("test_write_ed25519_combined_peer_id_raw2 key_data:\n", key_data)
        print("test_write_ed25519_combined_peer_id_raw2 key_data:\n", len(key_data))

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
        # private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data)

        assert raw_private_key == private_key.private_bytes_raw()
        print("test_write_ed25519_combined_peer_id_raw2 private_key.private_bytes_raw():\n", private_key.private_bytes_raw())
        print("test_write_ed25519_combined_peer_id_raw2 private_key.private_bytes_raw():\n", len(private_key.private_bytes_raw()))

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        print("test_write_ed25519_combined_peer_id_raw2 public_key_bytes:\n", public_key_bytes)
        print("test_write_ed25519_combined_peer_id_raw2 public_key_bytes:\n", len(public_key_bytes))

        assert raw_public_key == public_key_bytes

        combined_key_bytes = private_key.private_bytes_raw() + public_key_bytes
        # combined_key_bytes = public_key_bytes
        print("test_write_ed25519_combined_peer_id_raw2 combined_key_bytes:\n", combined_key_bytes)

        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.Ed25519,
            data=combined_key_bytes,
        ).SerializeToString()
        print("test_write_ed25519_combined_peer_id_raw2 encoded_public_key:\n", encoded_public_key)

        # encoded_public_key_sha256 = hashlib.sha256(encoded_public_key).digest()
        # encoded_public_key_peer_id = PeerID(encoded_public_key_sha256)
        # print("test_write_ed25519_combined_peer_id_raw2 encoded_public_key_peer_id", encoded_public_key_peer_id)

        encoded_digest = multihash.encode(
            hashlib.sha256(encoded_public_key).digest(),
            multihash.coerce_code("sha2-256"),
        )
        print("test_write_ed25519_combined_peer_id_raw2 encoded_digest", encoded_digest)

        peer_id = PeerID(encoded_digest)
        print("test_write_ed25519_combined_peer_id_raw2 peer_id", peer_id)

        peer_id_to_bytes = peer_id.to_bytes()

        assert encoded_digest == peer_id_to_bytes

    p2p = await P2P.create(identity_path='tests/ed25519/private_key_raw_pem2.key')

    p2p_peer_id = p2p.peer_id

    print("test_write_ed25519_combined_peer_id_raw2 p2p_peer_id", p2p_peer_id)


    await p2p.shutdown()


# pytest tests/ed25519/test_auth.py::test_write_ed25519_combined_peer_id_raw3 -rP

@pytest.mark.asyncio
async def test_write_ed25519_combined_peer_id_raw3():
    private_key = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
-----END PRIVATE KEY-----"""

    pem_private_key = serialization.load_pem_private_key(private_key, password=None)

    raw_private_key = pem_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,  # DER format
        format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
        encryption_algorithm=serialization.NoEncryption()  # No encryption
    )

    raw_public_key = pem_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    combined_key_bytes = raw_private_key + raw_public_key

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

    with open('tests/ed25519/private_key_raw_pem3.key', "wb") as f:
        f.write(protobuf.SerializeToString())

    with open('tests/ed25519/private_key_raw_pem3.key', "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])

        assert raw_private_key == private_key.private_bytes_raw()

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        assert raw_public_key == public_key_bytes

        combined_key_bytes = private_key.private_bytes_raw() + public_key_bytes

        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.Ed25519,
            data=public_key_bytes,
        ).SerializeToString()

        print("encoded_public_key, :", encoded_public_key)
        print("encoded_public_key, :", len(encoded_public_key))

        encoded_public_key = b"\x00$" + encoded_public_key

        peer_id = PeerID(encoded_public_key)

        peer_id_to_bytes = peer_id.to_bytes()

        assert encoded_public_key == peer_id_to_bytes

    p2p = await P2P.create(identity_path='tests/ed25519/private_key_raw_pem3.key')

    p2p_peer_id = p2p.peer_id

    assert p2p_peer_id == peer_id

    await p2p.shutdown()

# # pytest tests/ed25519/test_auth.py::test_write_ed25519_combined_peer_id_der -rP

# @pytest.mark.asyncio
# async def test_write_ed25519_combined_peer_id_der():
#     # test writing
#     private_key = b"""-----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
# -----END PRIVATE KEY-----"""


#     PrivateKeyImpl.from_seed

@pytest.mark.asyncio
async def test_valid_request_and_response():
    client_authorizer = MockAuthorizer(Ed25519PrivateKey())
    service_authorizer = MockAuthorizer(Ed25519PrivateKey())

    print("service_authorizer.local_public_key", service_authorizer.local_public_key.to_bytes())

    request = dht_pb2.PingRequest()
    request.peer.node_id = b"ping"
    await client_authorizer.sign_request(request, service_authorizer.local_public_key)
    assert await service_authorizer.validate_request(request)

    response = dht_pb2.PingResponse()
    response.peer.node_id = b"pong"
    await service_authorizer.sign_response(response, request)
    assert await client_authorizer.validate_response(response, request)


@pytest.mark.asyncio
async def test_invalid_access_token():
    client_authorizer = MockAuthorizer(Ed25519PrivateKey())
    service_authorizer = MockAuthorizer(Ed25519PrivateKey())

    request = dht_pb2.PingRequest()
    request.peer.node_id = b"ping"
    await client_authorizer.sign_request(request, service_authorizer.local_public_key)

    # Break the access token signature
    request.auth.client_access_token.signature = b"broken"

    assert not await service_authorizer.validate_request(request)

    response = dht_pb2.PingResponse()
    response.peer.node_id = b"pong"
    await service_authorizer.sign_response(response, request)

    # Break the access token signature
    response.auth.service_access_token.signature = b"broken"

    assert not await client_authorizer.validate_response(response, request)


@pytest.mark.asyncio
async def test_invalid_signatures():
    client_authorizer = MockAuthorizer(Ed25519PrivateKey())
    service_authorizer = MockAuthorizer(Ed25519PrivateKey())

    request = dht_pb2.PingRequest()
    request.peer.node_id = b"true-ping"
    await client_authorizer.sign_request(request, service_authorizer.local_public_key)

    # A man-in-the-middle attacker changes the request content
    request.peer.node_id = b"fake-ping"

    assert not await service_authorizer.validate_request(request)

    response = dht_pb2.PingResponse()
    response.peer.node_id = b"true-pong"
    await service_authorizer.sign_response(response, request)

    # A man-in-the-middle attacker changes the response content
    response.peer.node_id = b"fake-pong"

    assert not await client_authorizer.validate_response(response, request)


@pytest.mark.asyncio
async def test_auth_rpc_wrapper():
    class Servicer:
        async def rpc_increment(self, request: dht_pb2.PingRequest) -> dht_pb2.PingResponse:
            assert request.peer.node_id == b"ping"
            assert request.auth.client_access_token.username == "alice"

            response = dht_pb2.PingResponse()
            response.peer.node_id = b"pong"
            return response

    class Client:
        def __init__(self, servicer: Servicer):
            self._servicer = servicer

        async def rpc_increment(self, request: dht_pb2.PingRequest) -> dht_pb2.PingResponse:
            return await self._servicer.rpc_increment(request)

    servicer = AuthRPCWrapper(Servicer(), AuthRole.SERVICER, MockAuthorizer(Ed25519PrivateKey(), "bob"))
    client = AuthRPCWrapper(Client(servicer), AuthRole.CLIENT, MockAuthorizer(Ed25519PrivateKey(), "alice"))

    request = dht_pb2.PingRequest()
    request.peer.node_id = b"ping"

    response = await client.rpc_increment(request)

    assert response.peer.node_id == b"pong"
    assert response.auth.service_access_token.username == "bob"

# pytest tests/ed25519/test_auth.py::test_valid_request_and_response_2 -rP

@pytest.mark.asyncio
async def test_valid_request_and_response_2():
    test_rsa1 = Ed25519PrivateKey()
    test_rsa2 = Ed25519PrivateKey()
    client_authorizer = MockAuthorizer2(Ed25519PrivateKey())
    service_authorizer = MockAuthorizer2(Ed25519PrivateKey())
    fake_authorizer = MockAuthorizer2(Ed25519PrivateKey())

    request = dht_pb2.PingRequest()
    client_node_id = DHTID.generate()
    print("client_node_id", client_node_id)
    print("client_node_id", DHTID.from_bytes(client_node_id.to_bytes()))
    request.peer.node_id = client_node_id.to_bytes()
    # request.auth.service_public_key = client_authorizer.local_public_key.to_bytes()
    request.auth.client_access_token.public_key = client_authorizer.local_public_key.to_bytes()
    print("test_valid_request_and_response_2 request", request)
    await client_authorizer.sign_request(request, service_authorizer.local_public_key)
    assert await service_authorizer.validate_request(request)

    response = dht_pb2.PingResponse()
    service_node_id = DHTID.generate()
    print("service_node_id", service_node_id)
    print("service_node_id", service_node_id.to_bytes())
    print("service_node_id", DHTID.from_bytes(service_node_id.to_bytes()))
    response.peer.node_id = service_node_id.to_bytes()

    await service_authorizer.sign_response(response, request)
    assert await client_authorizer.validate_response(response, request)

# pytest tests/ed25519/test_auth.py::test_valid_request_and_response_invalid -rP

@pytest.mark.asyncio
async def test_valid_request_and_response_invalid():
    private_key = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
-----END PRIVATE KEY-----"""

    private_key = serialization.load_pem_private_key(private_key, password=None)
    
    raw_private_key = private_key.private_bytes_raw()

    raw_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,  # DER format
        format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
        encryption_algorithm=serialization.NoEncryption()  # No encryption
    )

    raw_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    combined_key_bytes = raw_private_key + raw_public_key
    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

    with open(f"tests/private_key_client.key", "wb") as f:
        f.write(protobuf.SerializeToString())

    with open(f"tests/private_key_client.key", "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
        ed25519_private_key = Ed25519PrivateKey(private_key=private_key)
        client_authorizer = MockAuthorizer2(ed25519_private_key)

    private_key = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGd73zfxu+jH4XPc4BWs9FG/38CDEw59RMlkw13W+e2f
-----END PRIVATE KEY-----"""

    private_key = serialization.load_pem_private_key(private_key, password=None)
    
    raw_private_key = private_key.private_bytes_raw()

    # raw_private_key = raw_private_key.private_bytes(
    #     encoding=serialization.Encoding.Raw,  # DER format
    #     format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
    #     encryption_algorithm=serialization.NoEncryption()  # No encryption
    # )

    raw_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    combined_key_bytes = raw_private_key + raw_public_key
    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

    with open(f"tests/private_key_service.key", "wb") as f:
        f.write(protobuf.SerializeToString())

    with open(f"tests/private_key_service.key", "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
        ed25519_private_key = Ed25519PrivateKey(private_key=private_key)
        service_authorizer = MockAuthorizer2(ed25519_private_key)

    fake_service_authorizer = MockAuthorizer2(Ed25519PrivateKey())

    # invalid validate request
    request = dht_pb2.PingRequest()
    client_node_id = DHTID.generate()
    request.peer.node_id = client_node_id.to_bytes()
    request.auth.client_access_token.public_key = client_authorizer.local_public_key.to_bytes()
    # wrong public key
    await client_authorizer.sign_request(request, fake_service_authorizer.local_public_key)
    print("test_valid_request_and_response_invalid request", request)
    assert not await service_authorizer.validate_request(request)

    response = dht_pb2.PingResponse()
    service_node_id = DHTID.generate()
    response.peer.node_id = service_node_id.to_bytes()
    await service_authorizer.sign_response(response, request)
    assert await client_authorizer.validate_response(response, request)

    # bad validate response
    request = dht_pb2.PingRequest()
    client_node_id = DHTID.generate()
    request.peer.node_id = client_node_id.to_bytes()
    request.auth.client_access_token.public_key = client_authorizer.local_public_key.to_bytes()
    # wrong public key
    await client_authorizer.sign_request(request, service_authorizer.local_public_key)
    print("test_valid_request_and_response_invalid request", request)
    assert await service_authorizer.validate_request(request)

    response = dht_pb2.PingResponse()
    service_node_id = DHTID.generate()
    response.peer.node_id = service_node_id.to_bytes()
    await service_authorizer.sign_response(response, request)
    assert await client_authorizer.validate_response(response, request)
