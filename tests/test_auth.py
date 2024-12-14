from datetime import datetime, timedelta
import hashlib
import secrets
from typing import Optional

import multihash
import pytest

from hivemind.proto import dht_pb2
from hivemind.proto.auth_pb2 import AccessToken
from cryptography.hazmat.primitives import serialization
from hivemind.dht.routing import DHTID
from hivemind.p2p.p2p_daemon_bindings.datastructures import PeerID
from hivemind.utils.auth import AuthRole, AuthRPCWrapper, AuthorizedRequestBase, AuthorizedResponseBase, AuthorizerBase, TokenAuthorizerBase
from hivemind.utils.crypto import RSAPrivateKey, RSAPublicKey
from hivemind.utils.logging import get_logger
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from hivemind.proto import crypto_pb2
from hivemind.utils.timed_storage import TimedStorage, get_dht_time

logger = get_logger(__name__)

# pytest tests/test_auth.py -rP


class MockAuthorizer(TokenAuthorizerBase):
    _authority_private_key = None
    _authority_public_key = None

    def __init__(self, local_private_key: Optional[RSAPrivateKey], username: str = "mock"):
        super().__init__(local_private_key)

        self._username = username
        self._authority_public_key = None

    async def get_token(self) -> AccessToken:
        if MockAuthorizer._authority_private_key is None:
            MockAuthorizer._authority_private_key = RSAPrivateKey()

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


@pytest.mark.asyncio
async def test_valid_request_and_response():
    client_authorizer = MockAuthorizer(RSAPrivateKey())
    service_authorizer = MockAuthorizer(RSAPrivateKey())

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
    client_authorizer = MockAuthorizer(RSAPrivateKey())
    service_authorizer = MockAuthorizer(RSAPrivateKey())

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

# pytest tests/test_auth.py::test_invalid_signatures -rP

@pytest.mark.asyncio
async def test_invalid_signatures():
    client_authorizer = MockAuthorizer(RSAPrivateKey())
    service_authorizer = MockAuthorizer(RSAPrivateKey())

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

    servicer = AuthRPCWrapper(Servicer(), AuthRole.SERVICER, MockAuthorizer(RSAPrivateKey(), "bob"))
    client = AuthRPCWrapper(Client(servicer), AuthRole.CLIENT, MockAuthorizer(RSAPrivateKey(), "alice"))

    request = dht_pb2.PingRequest()
    request.peer.node_id = b"ping"

    response = await client.rpc_increment(request)

    assert response.peer.node_id == b"pong"
    assert response.auth.service_access_token.username == "bob"


class MockAuthorizer2(AuthorizerBase):
    def __init__(self, local_private_key: RSAPrivateKey):
        super().__init__()

        self._local_private_key = local_private_key
        self._local_public_key = local_private_key.get_public_key()
        print("MockAuthorizer2 self._local_public_key", self._local_public_key.to_bytes())
        print("MockAuthorizer2 self._local_public_key", self._local_public_key.to_bytes())

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

    async def sign_request(self, request: AuthorizedRequestBase, service_public_key: Optional[RSAPublicKey]) -> None:
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
        client_public_key = RSAPublicKey.from_bytes(auth.client_access_token.public_key)
        
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
        
        service_public_key = RSAPublicKey.from_bytes(auth.service_access_token.public_key)
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
    def local_public_key(self) -> RSAPublicKey:
        return self._local_public_key

# pytest tests/test_auth.py::test_valid_request_and_response_2 -rP

@pytest.mark.asyncio
async def test_valid_request_and_response_2():
    test_rsa1 = RSAPrivateKey()
    test_rsa2 = RSAPrivateKey()
    client_authorizer = MockAuthorizer2(RSAPrivateKey())
    service_authorizer = MockAuthorizer2(RSAPrivateKey())

    request = dht_pb2.PingRequest()
    client_node_id = DHTID.generate()
    print("client_node_id", client_node_id)
    print("client_node_id", DHTID.from_bytes(client_node_id.to_bytes()))
    request.peer.node_id = client_node_id.to_bytes()
    # request.auth.service_public_key = client_authorizer.local_public_key.to_bytes()
    request.auth.client_access_token.public_key = client_authorizer.local_public_key.to_bytes()
    await client_authorizer.sign_request(request, service_authorizer.local_public_key)
    assert await service_authorizer.validate_request(request)

    response = dht_pb2.PingResponse()
    service_node_id = DHTID.generate()
    print("service_node_id", service_node_id)
    print("service_node_id", service_node_id.to_bytes())
    print("service_node_id", DHTID.from_bytes(service_node_id.to_bytes()))
    response.peer.node_id = service_node_id.to_bytes()
    # response.auth.service_access_token = client_authorizer.local_public_key.to_bytes()
    # response.auth.service_access_token.CopyFrom(client_authorizer.local_public_key.to_bytes())

    await service_authorizer.sign_response(response, request)
    assert await client_authorizer.validate_response(response, request)


# pytest tests/test_auth.py::test_valid_request_and_response_invalid -rP

@pytest.mark.asyncio
async def test_valid_request_and_response_invalid():
    # private_key = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048,
    # )
    private_key = b"""-----BEGIN PRIVATE KEY-----
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

    rsa_private_key = serialization.load_pem_private_key(private_key, password=None)

    private_key = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.RSA, data=private_key)

    with open(f"tests/private_key_client.key", "wb") as f:
        f.write(protobuf.SerializeToString())

    with open(f"tests/private_key_client.key", "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        private_key = serialization.load_der_private_key(key_data, password=None)
        rsa_private_key = RSAPrivateKey(private_key=private_key)
        client_authorizer = MockAuthorizer2(rsa_private_key)

    # private_key = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048,
    # )
    private_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----"""

    rsa_private_key = serialization.load_pem_private_key(private_key, password=None)
    
    private_key = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.RSA, data=private_key)

    with open(f"tests/private_key_service.key", "wb") as f:
        f.write(protobuf.SerializeToString())

    with open(f"tests/private_key_service.key", "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        private_key = serialization.load_der_private_key(key_data, password=None)
        rsa_private_key = RSAPrivateKey(private_key=private_key)
        service_authorizer = MockAuthorizer2(rsa_private_key)

    fake_service_authorizer = MockAuthorizer2(RSAPrivateKey().process_wide())

    request = dht_pb2.PingRequest()
    client_node_id = DHTID.generate()
    request.peer.node_id = client_node_id.to_bytes()
    request.auth.client_access_token.public_key = client_authorizer.local_public_key.to_bytes()
    await client_authorizer.sign_request(request, service_authorizer.local_public_key)
    print("test_valid_request_and_response_invalid request", request)
    assert await service_authorizer.validate_request(request)

    response = dht_pb2.PingResponse()
    service_node_id = DHTID.generate()
    response.peer.node_id = service_node_id.to_bytes()
    await service_authorizer.sign_response(response, request)
    assert await client_authorizer.validate_response(response, request)


    # client_authorizer = MockAuthorizer2(RSAPrivateKey().process_wide())
    # service_authorizer = MockAuthorizer2(RSAPrivateKey().process_wide())

    # request = dht_pb2.PingRequest()
    # request.peer.node_id = b"true-ping"
    # await client_authorizer.sign_request(request, service_authorizer.local_public_key)

    # # A man-in-the-middle attacker changes the request content
    # request.peer.node_id = b"fake-ping"

    # assert not await service_authorizer.validate_request(request)

    # response = dht_pb2.PingResponse()
    # response.peer.node_id = b"true-pong"
    # await service_authorizer.sign_response(response, request)

    # # A man-in-the-middle attacker changes the response content
    # response.peer.node_id = b"fake-pong"

    # assert not await client_authorizer.validate_response(response, request)

@pytest.mark.asyncio
async def test_authorizer():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize the private key to DER format
    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.RSA, data=private_key)

    with open(f"tests/private_key_test.key", "wb") as f:
        f.write(protobuf.SerializeToString())

    with open(f"tests/private_key_test.key", "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        private_key = serialization.load_der_private_key(key_data, password=None)
        rsa_private_key = RSAPrivateKey(private_key=private_key)
        # private_key = private_key.private_bytes(
        #     encoding=serialization.Encoding.DER,
        #     format=serialization.PrivateFormat.TraditionalOpenSSL,
        #     encryption_algorithm=serialization.NoEncryption()
        # )
        # protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.RSA, data=private_key)
        print("test_authorizer private_key", rsa_private_key.get_public_key())
        mock_auth = MockAuthorizer2(rsa_private_key)


