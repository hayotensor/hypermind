from datetime import datetime, timedelta
import hashlib
import os
from typing import Optional

import multihash
import pytest

from hivemind.proto import dht_pb2
from hivemind.proto.auth_pb2 import AccessToken
from hivemind.p2p.p2p_daemon import P2P
from hivemind.p2p.p2p_daemon_bindings.datastructures import PeerID
from hivemind.utils.auth import AuthRole, AuthRPCWrapper, TokenAuthorizerBase
from hivemind.utils.crypto import Ed25519PrivateKey
from hivemind.utils.logging import get_logger
from cryptography.hazmat.primitives import serialization
from hivemind.proto import crypto_pb2, p2pd_pb2
from cryptography.hazmat.primitives.asymmetric import ed25519

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
    # print("test_write_ed25519_peer_id protobuf:\n", protobuf)

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

    # protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=private_key)

    with open('tests/ed25519/private_key_raw_pem.key', "wb") as f:
        f.write(protobuf.SerializeToString())

    with open('tests/ed25519/private_key_raw_pem.key', "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        print("test_write_ed25519_combined_peer_id_raw key_data:\n", key_data)
        print("test_write_ed25519_combined_peer_id_raw key_data:\n", key_data[:32])

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
        print("test_write_ed25519_combined_peer_id_raw raw_private_key:\n", raw_private_key)
        print("test_write_ed25519_combined_peer_id_raw private_key    :\n", private_key)
        print("test_write_ed25519_combined_peer_id_raw private_key raw:\n", private_key.private_bytes_raw())

        assert raw_private_key == private_key.private_bytes_raw()

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        print("test_write_ed25519_combined_peer_id_raw public_key_bytes:\n", public_key_bytes)
        print("test_write_ed25519_combined_peer_id_raw public_key_bytes:\n", len(public_key_bytes))

        assert raw_public_key == public_key_bytes

        combined_key_bytes = private_key.private_bytes_raw() + public_key_bytes
    #     print("test_write_ed25519_combined_peer_id_raw combined_key_bytes:\n", combined_key_bytes)
    #     print("test_write_ed25519_combined_peer_id_raw combined_key_bytes:\n", len(combined_key_bytes))

        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.Ed25519,
            data=combined_key_bytes,
        ).SerializeToString()
    #     print("test_write_ed25519_combined_peer_id_raw encoded_public_key:\n", encoded_public_key)
    #     print("encoded_public_key pem len:\n", len(encoded_public_key))

        encoded_digest = multihash.encode(
            hashlib.sha256(encoded_public_key).digest(),
            multihash.coerce_code("sha2-256"),
        )
        print("test_write_ed25519_combined_peer_id_raw encoded_digest:\n", encoded_digest)


        peer_id = PeerID(encoded_digest)
        print("test_write_ed25519_combined_peer_id_raw peer_id", peer_id)

        peer_id_to_bytes = peer_id.to_bytes()

        assert encoded_digest == peer_id_to_bytes


    p2p = await P2P.create(identity_path='private_key_raw_pem.key')

    p2p_peer_id = p2p.peer_id

    print("test_write_ed25519_combined_peer_id_raw p2p_peer_id", p2p_peer_id)

    await p2p.shutdown()

# @pytest.mark.asyncio
# async def test_write_ed25519_peer_id():
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

#     protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=private_key)
#     print("test_write_ed25519_peer_id protobuf:\n", protobuf)

#     with open('tests/ed25519/private_key_2.pem', "wb") as f:
#         f.write(protobuf.SerializeToString())

#     with open('tests/ed25519/private_key_2.pem', "rb") as f:
#         data = f.read()
#         key_data = crypto_pb2.PrivateKey.FromString(data).data
#         print("test_write_ed25519_peer_id key_data:\n", key_data)

#         private_key = serialization.load_pem_private_key(key_data, password=None)
#         print("test_write_ed25519_peer_id private_key:\n", private_key)

#         encoded_public_key = private_key.public_key().public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo,
#         )
#         print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)

#         encoded_public_key = crypto_pb2.PublicKey(
#             key_type=crypto_pb2.Ed25519,
#             data=encoded_public_key,
#         ).SerializeToString()
#         print("test_write_ed25519_peer_id encoded_public_key:\n", encoded_public_key)

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

# @pytest.mark.asyncio
# async def test_ed25519_peer_id():
#     # P2P.generate_identity("tests/ed25519/private_key.key")
#     # with open('tests/ed25519/private_key.key', "rb") as f:
#     #     # private_key = serialization.load_der_private_key(f.read(), password=None)
#     #     # print("test_ed25519_peer_id private_key", private_key)
#     #     peer_id = PeerID.from_identity(f.read())
#     #     print("test_ed25519_peer_id peer_id", peer_id)
#     pkcs8Pem = b"""-----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VwBCIEIH7sjlQYpBCnodJqPqYS2441L4wOOqyfLoc/SzTTC1h8
# -----END PRIVATE KEY-----"""

# #     pkcs8Pem = b"""-----BEGIN PRIVATE KEY-----
# # MC4CAQAwBQYDK2VwBCIEIEv8udLsDLHKD/jYY5Zb9VfhMD70AoTWTTFSmy7nOwKm
# # -----END PRIVATE KEY-----"""

#     private_key = serialization.load_pem_private_key(pkcs8Pem, password=None)
#     print("private_key:\n", private_key)

#     privateOpenSshPem = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.OpenSSH,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     print("private key:\n", privateOpenSshPem.decode())

#     encoded_public_key = private_key.public_key().public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo,
#     )
#     print("encoded_public_key:\n", encoded_public_key)

#     encoded_public_key_non_serialized = crypto_pb2.PublicKey(
#         key_type=crypto_pb2.Ed25519,
#         data=encoded_public_key,
#     )
#     print("encoded_public_key_non_serialized", encoded_public_key_non_serialized)

#     encoded_public_key = crypto_pb2.PublicKey(
#         key_type=crypto_pb2.Ed25519,
#         data=encoded_public_key,
#     ).SerializeToString()
#     print("test_identity encoded_public_key", encoded_public_key)

#     encoded_digest = multihash.encode(
#         hashlib.sha256(encoded_public_key).digest(),
#         multihash.coerce_code("sha2-256"),
#     )
#     print("test_identity encoded_digest", encoded_digest)

#     print("test_identity encoded_digest", PeerID(encoded_digest))


    # using bytes
    # with open('tests/ed25519/private_key.pem', "rb") as f:

    #     private_key = serialization.load_pem_private_key(f.read(), password=None)
    #     print("test_identity private_key", private_key)

    #     encoded_public_key = private_key.public_key().public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo,
    #     )
    #     print("encoded_public_key:\n", encoded_public_key)

        # peer_id = PeerID.from_identity(f.read())
        # print("test_identity peer_id", peer_id)
        # test = f.read().to_bytes()
        # print("test_identity test", test)
        # key_data = crypto_pb2.PrivateKey.FromString(f.read()).data
        # print("test_identity key_data", key_data)

    # data = pkcs8Pem.encode()
    # print("test_identity data", data)
    

    # data_bytes = ed25519.Ed25519PrivateKey.from_private_bytes(data)
    # print("test_identity data_bytes", data_bytes)

    # key_data = crypto_pb2.PrivateKey.FromString(data).data
    # print("test_identity key_data", key_data)

# @pytest.mark.asyncio
# async def test_ed25519_peer_id_2():
#     private_key = Ed25519PrivateKey()
#     print("private_key", private_key)
#     public_key = private_key.get_public_key()
#     print("public_key", public_key)
#     public_key_to_bytes = public_key.to_bytes()
#     print("public_key_to_bytes", public_key_to_bytes)
#     private_key_process_wide = private_key.process_wide()
#     print("private_key_process_wide", private_key_process_wide)
#     private_key_to_bytes = private_key.to_bytes()
#     print("private_key_to_bytes", private_key_to_bytes)

#     # private_key = serialization.load_der_private_key(key_data, password=None)

#     # encoded_public_key = private_key.public_key().public_bytes(
#     #     encoding=serialization.Encoding.Raw,
#     #     format=serialization.PublicFormat.SubjectPublicKeyInfo,
#     # )
#     # print("encoded_public_key", encoded_public_key)




#     protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=private_key.to_bytes())
#     print("generate_identity protobuf", protobuf)

#     protobuf_serialized = protobuf.SerializeToString()
#     print("protobuf_serialized", protobuf_serialized)

#     key_data = crypto_pb2.PrivateKey.FromString(protobuf_serialized).data
#     print("key_data", key_data)

#     # private_key = serialization.load_der_private_key(key_data, password=None)
#     # print("private_key", private_key)






#     # path = os.path.abspath('tests/ed25519/private_key.key')
#     # server = await P2P.create(identity_path=path)

#     # print("test_identity server", server.peer_id)

#     # with open('tests/ed25519/private_key.key', "rb") as f:
#     #     peer_id = PeerID.from_identity(f.read())
#     #     print("test_identity peer_id", peer_id)

#     # with open('tests/ed25519/private_key.key', "rb") as f:
#         # print("test_identity f.read()", f.read())
#         # data = f.read()
#         # key_data = crypto_pb2.PrivateKey.FromString(data).data
#         # load_der_parameters
#         # load_der_private_key
#         # load_der_public_key
#         # load_pem_parameters
#         # load_pem_private_key
#         # load_pem_public_key
#         # private_key = serialization.load_pem_private_key(key_data, password=None)
#         # private_key = serialization.load_der_private_key(key_data, password=None)

#         # print("test_identity private_key.public_key()", private_key.public_key())

#         # encoded_public_key = private_key.public_key().public_bytes(
#         #     encoding=serialization.Encoding.DER,
#         #     format=serialization.PublicFormat.SubjectPublicKeyInfo,
#         # )
#         # print("test_identity encoded_public_key", encoded_public_key)

#         # encoded_public_key_non_serialized = crypto_pb2.PublicKey(
#         #     key_type=crypto_pb2.Ed25519,
#         #     data=encoded_public_key,
#         # )
#         # print("test_identity encoded_public_key_non_serialized", encoded_public_key_non_serialized)


#         # encoded_public_key = crypto_pb2.PublicKey(
#         #     key_type=crypto_pb2.Ed25519,
#         #     data=encoded_public_key,
#         # ).SerializeToString()
#         # print("test_identity encoded_public_key", encoded_public_key)

#         # encoded_digest = multihash.encode(
#         #     hashlib.sha256(encoded_public_key).digest(),
#         #     multihash.coerce_code("sha2-256"),
#         # )
#         # print("test_identity encoded_digest", encoded_digest)

#     # await server.shutdown()

# @pytest.mark.asyncio
# async def test_valid_request_and_response():
#     client_authorizer = MockAuthorizer(Ed25519PrivateKey())
#     service_authorizer = MockAuthorizer(Ed25519PrivateKey())

#     print("service_authorizer.local_public_key", service_authorizer.local_public_key.to_bytes())

#     request = dht_pb2.PingRequest()
#     request.peer.node_id = b"ping"
#     await client_authorizer.sign_request(request, service_authorizer.local_public_key)
#     assert await service_authorizer.validate_request(request)

#     response = dht_pb2.PingResponse()
#     response.peer.node_id = b"pong"
#     await service_authorizer.sign_response(response, request)
#     assert await client_authorizer.validate_response(response, request)


# @pytest.mark.asyncio
# async def test_invalid_access_token():
#     client_authorizer = MockAuthorizer(Ed25519PrivateKey())
#     service_authorizer = MockAuthorizer(Ed25519PrivateKey())

#     request = dht_pb2.PingRequest()
#     request.peer.node_id = b"ping"
#     await client_authorizer.sign_request(request, service_authorizer.local_public_key)

#     # Break the access token signature
#     request.auth.client_access_token.signature = b"broken"

#     assert not await service_authorizer.validate_request(request)

#     response = dht_pb2.PingResponse()
#     response.peer.node_id = b"pong"
#     await service_authorizer.sign_response(response, request)

#     # Break the access token signature
#     response.auth.service_access_token.signature = b"broken"

#     assert not await client_authorizer.validate_response(response, request)


# @pytest.mark.asyncio
# async def test_invalid_signatures():
#     client_authorizer = MockAuthorizer(Ed25519PrivateKey())
#     service_authorizer = MockAuthorizer(Ed25519PrivateKey())

#     request = dht_pb2.PingRequest()
#     request.peer.node_id = b"true-ping"
#     await client_authorizer.sign_request(request, service_authorizer.local_public_key)

#     # A man-in-the-middle attacker changes the request content
#     request.peer.node_id = b"fake-ping"

#     assert not await service_authorizer.validate_request(request)

#     response = dht_pb2.PingResponse()
#     response.peer.node_id = b"true-pong"
#     await service_authorizer.sign_response(response, request)

#     # A man-in-the-middle attacker changes the response content
#     response.peer.node_id = b"fake-pong"

#     assert not await client_authorizer.validate_response(response, request)


# @pytest.mark.asyncio
# async def test_auth_rpc_wrapper():
#     class Servicer:
#         async def rpc_increment(self, request: dht_pb2.PingRequest) -> dht_pb2.PingResponse:
#             assert request.peer.node_id == b"ping"
#             assert request.auth.client_access_token.username == "alice"

#             response = dht_pb2.PingResponse()
#             response.peer.node_id = b"pong"
#             return response

#     class Client:
#         def __init__(self, servicer: Servicer):
#             self._servicer = servicer

#         async def rpc_increment(self, request: dht_pb2.PingRequest) -> dht_pb2.PingResponse:
#             return await self._servicer.rpc_increment(request)

#     servicer = AuthRPCWrapper(Servicer(), AuthRole.SERVICER, MockAuthorizer(Ed25519PrivateKey(), "bob"))
#     client = AuthRPCWrapper(Client(servicer), AuthRole.CLIENT, MockAuthorizer(Ed25519PrivateKey(), "alice"))

#     request = dht_pb2.PingRequest()
#     request.peer.node_id = b"ping"

#     response = await client.rpc_increment(request)

#     assert response.peer.node_id == b"pong"
#     assert response.auth.service_access_token.username == "bob"
