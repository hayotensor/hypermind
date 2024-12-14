import asyncio
import base64
import hashlib
import multiprocessing as mp
import os
import subprocess
import tempfile
from contextlib import closing
from functools import partial
from typing import List

import base58
import multihash
import numpy as np
import pytest

from hivemind.proto import crypto_pb2
from cryptography.hazmat.primitives import serialization
from hivemind.dht.routing import NodeIDGenerator
from hivemind.p2p import P2P, P2PDaemonError, P2PHandlerError
from hivemind.p2p.multiaddr import Multiaddr
from hivemind.proto import dht_pb2, test_pb2
from hivemind.p2p.p2p_daemon_bindings.datastructures import PeerID
from hivemind.utils.crypto import RSAPrivateKey
from hivemind.utils.logging import get_logger
from hivemind.utils.serializer import MSGPackSerializer

from test_utils.networking import get_free_port

logger = get_logger(__name__)

# pytest tests/test_peer_id.py -rP

# @pytest.mark.asyncio
# async def test_identity():
#     path = os.path.abspath('/home/bob/hypermind-signature/tests/private_key.key')
#     # server = await P2P.create(identity_path=path)
#     server = await P2P.create()

#     print("test_identity server", server.peer_id)

#     await server.shutdown()

# @pytest.mark.asyncio
# async def test_identity2():
#     private_key = RSAPrivateKey()
#     protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.RSA, data=private_key.to_bytes())
#     print("test_identity2 protobuf", protobuf)
#     protobuf_serialize = protobuf.SerializeToString()
#     print("test_identity2 protobuf_serialize", protobuf_serialize)

#     key_data = crypto_pb2.PrivateKey.FromString(protobuf_serialize).data
#     print("test_identity2 key_data", key_data)

#     private_key = serialization.load_der_private_key(key_data, password=None)
#     print("test_identity2 private_key", private_key)

#     encoded_public_key = private_key.public_key().public_bytes(
#         encoding=serialization.Encoding.DER,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo,
#     )
#     print("test_identity2 encoded_public_key", encoded_public_key)
#     encoded_public_key = crypto_pb2.PublicKey(
#         key_type=crypto_pb2.RSA,
#         data=encoded_public_key,
#     ).SerializeToString()
#     print("test_identity2 encoded_public_key", encoded_public_key)

#     encoded_digest = multihash.encode(
#         hashlib.sha256(encoded_public_key).digest(),
#         multihash.coerce_code("sha2-256"),
#     )

#     print("test_identity2 encoded_digest", encoded_digest)
#     print("test_identity2 encoded_digest", PeerID(encoded_digest))

# @pytest.mark.asyncio
# async def test_identity3():
# #     rsa_private_key = b"""-----BEGIN RSA PRIVATE KEY-----
# # MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
# # KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
# # o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
# # TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
# # 9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
# # v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
# # /5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
# # -----END RSA PRIVATE KEY-----"""

#     rsa_private_key = b"""-----BEGIN PRIVATE KEY-----
# MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDa3Ik+R/Wl/xLJ
# 6XJv1hod6MzW+dcUfEEe6sUyCB3PGWKqSiSaUeiouHIfZrcjeOG81HAG4yZ9Nvs+
# 1tlzAVjLMJdDfBHL7R/xPCQAaQ8cLYjPbpW6Aj6UH32bi46m+/ozzeVFEqFH2Od/
# XpkPEuLHDAo5WSJ2IvdZ4RUNMa55bJ3elMsq3cqnzWJxc4YNe1gtV/ARO64FKKZu
# 2oV6Britm4jxjkHxbLafcJvsLwFXKHU2KZdEcpNXNrldUV+OWW1sRUwaqjiKUQua
# Atjnty0xMxvZasm/iMoJ99REBDovcRDnQ4skPvYdWAmZV6l2zfCy2y4al5xpUChd
# KfOMvG9nAgMBAAECggEAB7zWSVJn9+dttZ/AQP3zzGznmQ4aMYo3Dy3DrQImc6T1
# HQokAyS0MgrbVgrenK1wZampEEVFnhWsiks0QuGgTwa3wlYHlwsaHwA+UZllRFzD
# wnmpZ3se1UPLwA0ODQ9JiD1WRrvi4dRkUtd4V9UWGW1uixqAomaYEiBoCyBfh8Fj
# hciq8pgQ09Y3uLejEW9Z31M90UYL/WmY2qGmbNnc8NurXqLnKbyF7Ob1fbqb9qEX
# Sg/TsyyBYi/zipuGXUG4C3JK6z/Xnfut3nMfJr1NEDjtUHdeIGPzXc32GDGpqw2j
# i83OLZKStPo6n7LtnBXRckfIyo6/sIgJhvc525HloQKBgQDa/auByYkMBExO9UZJ
# ODvXI60xZqMt9GF2bx8KdcR38r2RSQbaKXIRg/nSBoNd7JSQesE9h7eOsn8ww0hi
# vBDxRcpWCItyHp0Qts4CxOc9SqfihwKC0c9Ax2cjClGQXEXFBne/zcv3Ua4ayOoa
# Nhazg3GdD+/9AVLjNR9FQbEgMQKBgQD/2UQ/aEpP8Ncx4Fl016HqJbfgh3nBbGsC
# 5QySfsH/54wSJD66Bhubju+6rzBeOYPhu2UP7m1k6YOGG/YY6NA9tNyXiz259HQ+
# tnW8oPBxOUzZfFE66YSHaKWyM95uhjxbE5TiRwIoDqBdT1E9mdUDDssCQPR+q7+c
# jUaVrUt7FwKBgQC29ayuuJQ5Z/XhGebpEYRdUD9IwLmgkUZETr6eXJoSpMlgcqS4
# 7FuS6rJzmGF0vU26D/UW1Sa0n8jIEr+NThbRnT9Y9babV5xd9HzVr3CKsq7lAWtF
# pMkFFBPFIL/YXl8kJy0xIF1Cegl981IzJ/F7dVwcns4gkVSQ4zcHA8VaYQKBgDHy
# PkqKl4dHoxsPiycuOWO2fVEN4Y0LF1D3Wh73M/Q7RbL89Gnoa1dQ7ifpr22VmNNm
# e/JCP4TluVFjAAYY3R5OwomrGx/EQzVC9XUfjhDseL40cL8pez/cBAzn51J4TiwR
# hI0wA5HCWTgeFeQKtfTk3GjSOWjJKpzrT45EyGl9AoGBANWXaFCYMvGfg1ockV6k
# mTOE6+MANN/WyeZsH/L/PHkfGnKjItY9cmJE1SneCKoz5Ouvi4br5/j9RH0+xamk
# J4t6Z8sIKOuvGZtlegLtNhVF2zupLTa44w6sPFsB6eKfEnpEi0WrVYDTwVrks14y
# eO6/mHuREBujkJ5zVGAUeZal
# -----END PRIVATE KEY-----"""

#     protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.RSA, data=rsa_private_key)
#     print("test_identity3 protobuf:\n", protobuf)

#     with open('tests/private_key_2.key', "wb") as f:
#         f.write(protobuf.SerializeToString())


#     with open('tests/private_key_2.key', "rb") as f:
#         data = f.read()
#         key_data = crypto_pb2.PrivateKey.FromString(data).data
#         print("test_identity3 key_data:\n", key_data)

#         private_key = serialization.load_pem_private_key(key_data, password=None)
#         print("test_identity3 private_key:\n", private_key)

#         encoded_public_key = private_key.public_key().public_bytes(
#             encoding=serialization.Encoding.DER,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo,
#         )
#         print("test_identity3 encoded_public_key:\n", encoded_public_key)

#         encoded_public_key = crypto_pb2.PublicKey(
#             key_type=crypto_pb2.RSA,
#             data=encoded_public_key,
#         ).SerializeToString()
#         print("test_identity3 encoded_public_key:\n", encoded_public_key)

#         encoded_digest = multihash.encode(
#             hashlib.sha256(encoded_public_key).digest(),
#             multihash.coerce_code("sha2-256"),
#         )
#         print("test_identity3 encoded_digest:\n", encoded_digest)

#         print("test_identity3 encoded_digest", PeerID(encoded_digest))



@pytest.mark.asyncio
async def test_identity_der():
    rsa_private_key = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDa3Ik+R/Wl/xLJ
6XJv1hod6MzW+dcUfEEe6sUyCB3PGWKqSiSaUeiouHIfZrcjeOG81HAG4yZ9Nvs+
1tlzAVjLMJdDfBHL7R/xPCQAaQ8cLYjPbpW6Aj6UH32bi46m+/ozzeVFEqFH2Od/
XpkPEuLHDAo5WSJ2IvdZ4RUNMa55bJ3elMsq3cqnzWJxc4YNe1gtV/ARO64FKKZu
2oV6Britm4jxjkHxbLafcJvsLwFXKHU2KZdEcpNXNrldUV+OWW1sRUwaqjiKUQua
Atjnty0xMxvZasm/iMoJ99REBDovcRDnQ4skPvYdWAmZV6l2zfCy2y4al5xpUChd
KfOMvG9nAgMBAAECggEAB7zWSVJn9+dttZ/AQP3zzGznmQ4aMYo3Dy3DrQImc6T1
HQokAyS0MgrbVgrenK1wZampEEVFnhWsiks0QuGgTwa3wlYHlwsaHwA+UZllRFzD
wnmpZ3se1UPLwA0ODQ9JiD1WRrvi4dRkUtd4V9UWGW1uixqAomaYEiBoCyBfh8Fj
hciq8pgQ09Y3uLejEW9Z31M90UYL/WmY2qGmbNnc8NurXqLnKbyF7Ob1fbqb9qEX
Sg/TsyyBYi/zipuGXUG4C3JK6z/Xnfut3nMfJr1NEDjtUHdeIGPzXc32GDGpqw2j
i83OLZKStPo6n7LtnBXRckfIyo6/sIgJhvc525HloQKBgQDa/auByYkMBExO9UZJ
ODvXI60xZqMt9GF2bx8KdcR38r2RSQbaKXIRg/nSBoNd7JSQesE9h7eOsn8ww0hi
vBDxRcpWCItyHp0Qts4CxOc9SqfihwKC0c9Ax2cjClGQXEXFBne/zcv3Ua4ayOoa
Nhazg3GdD+/9AVLjNR9FQbEgMQKBgQD/2UQ/aEpP8Ncx4Fl016HqJbfgh3nBbGsC
5QySfsH/54wSJD66Bhubju+6rzBeOYPhu2UP7m1k6YOGG/YY6NA9tNyXiz259HQ+
tnW8oPBxOUzZfFE66YSHaKWyM95uhjxbE5TiRwIoDqBdT1E9mdUDDssCQPR+q7+c
jUaVrUt7FwKBgQC29ayuuJQ5Z/XhGebpEYRdUD9IwLmgkUZETr6eXJoSpMlgcqS4
7FuS6rJzmGF0vU26D/UW1Sa0n8jIEr+NThbRnT9Y9babV5xd9HzVr3CKsq7lAWtF
pMkFFBPFIL/YXl8kJy0xIF1Cegl981IzJ/F7dVwcns4gkVSQ4zcHA8VaYQKBgDHy
PkqKl4dHoxsPiycuOWO2fVEN4Y0LF1D3Wh73M/Q7RbL89Gnoa1dQ7ifpr22VmNNm
e/JCP4TluVFjAAYY3R5OwomrGx/EQzVC9XUfjhDseL40cL8pez/cBAzn51J4TiwR
hI0wA5HCWTgeFeQKtfTk3GjSOWjJKpzrT45EyGl9AoGBANWXaFCYMvGfg1ockV6k
mTOE6+MANN/WyeZsH/L/PHkfGnKjItY9cmJE1SneCKoz5Ouvi4br5/j9RH0+xamk
J4t6Z8sIKOuvGZtlegLtNhVF2zupLTa44w6sPFsB6eKfEnpEi0WrVYDTwVrks14y
eO6/mHuREBujkJ5zVGAUeZal
-----END PRIVATE KEY-----"""

    rsa_private_key = serialization.load_pem_private_key(rsa_private_key, password=None)

    # Serialize it to DER format
    derkey = rsa_private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.RSA, data=derkey)
    print("test_identity_der protobuf:\n", protobuf)

    with open('tests/private_key_dem.key', "wb") as f:
        f.write(protobuf.SerializeToString())


    with open('tests/private_key_dem.key', "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        print("test_identity_der key_data:\n", key_data)

        private_key = serialization.load_der_private_key(key_data, password=None)
        print("test_identity_der private_key:\n", private_key)

        print("test_identity_der private_key.public_key():\n", private_key.public_key())

        encoded_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        print("test_identity_der encoded_public_key:\n", encoded_public_key)

        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.RSA,
            data=encoded_public_key,
        ).SerializeToString()
        print("test_identity_der encoded_public_key:\n", encoded_public_key)

        encoded_digest = multihash.encode(
            hashlib.sha256(encoded_public_key).digest(),
            multihash.coerce_code("sha2-256"),
        )
        print("test_identity_der encoded_digest:\n", encoded_digest)
        print("test_identity_der encoded_digest:\n", len(encoded_digest))

        peer_id = PeerID(encoded_digest)
        print("test_identity_der peer_id", peer_id)

        peer_id_to_bytes = peer_id.to_bytes()
        print("test_identity_der peer_id_to_bytes", peer_id_to_bytes)

        assert encoded_digest == peer_id_to_bytes

        peer_id_from_bytes = PeerID(peer_id_to_bytes)
        print("test_identity_der peer_id_from_bytes", peer_id_from_bytes)

        assert peer_id == peer_id_from_bytes

        # node_id = NodeIDGenerator.generate_node_id(peer_id.to_bytes())
        # print(f"Deterministic Node ID: {node_id}")

        node_id = "0x" + base64.urlsafe_b64encode(peer_id.to_base58().encode()).decode()
        print(f"node_id ID: {node_id}")

        # Decode node_id to peer_id
        decoded_peer_id = base64.urlsafe_b64decode(node_id[2:].encode()).decode()
        print(f"Original Peer ID: {decoded_peer_id}")

        assert peer_id == decoded_peer_id

        # decoded_peer_id = base58.b58decode(peer_id.to_string())

        # # Decode the multihash
        # digest = multihash.decode(decoded_peer_id)

        # print(f"Hash Algorithm: digest", digest)  # Should be 'sha2-256'

        # print(f"Hash Algorithm: ", digest.code)  # Should be 'sha2-256'
        # print(f"SHA-256 Hash: {digest.digest.hex()}")


        # peer_id = multihash(sha256(der_encoded_rsa_public_key))

        # decoded_data = base58.b58decode(peer_id.to_string())
        # print("test_identity_der decoded_data", decoded_data)


        # public_key = serialization.load_der_public_key(decoded_data)
        # print("Public key successfully retrieved!", public_key)


        

        # peer_id_from_base58 = PeerID.from_base58(peer_id)
        # print("test_identity_der peer_id_from_base58", peer_id_from_base58)

    p2p = await P2P.create(identity_path='tests/private_key_dem.key')
    p2p_peer_id = p2p.peer_id

    print("test_identity_der p2p_peer_id", p2p_peer_id)
    assert p2p_peer_id == peer_id
    await p2p.shutdown()
