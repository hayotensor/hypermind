import asyncio
import functools
import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Optional

from hivemind.proto.auth_pb2 import AccessToken, RequestAuthInfo, ResponseAuthInfo
from hivemind.p2p.p2p_daemon_bindings.datastructures import PeerID
from hivemind.utils.crypto import Ed25519PrivateKey, Ed25519PublicKey
from hivemind.utils.logging import get_logger
from hivemind.utils.substrate import is_subnet_node_by_peer_id
from hivemind.utils.timed_storage import TimedStorage, get_dht_time
from hivemind.proto import crypto_pb2

from substrateinterface import SubstrateInterface

logger = get_logger(__name__)


class AuthorizedRequestBase:
    """
    Interface for protobufs with the ``RequestAuthInfo auth`` field. Used for type annotations only.
    """

    auth: RequestAuthInfo


class AuthorizedResponseBase:
    """
    Interface for protobufs with the ``ResponseAuthInfo auth`` field. Used for type annotations only.
    """

    auth: ResponseAuthInfo


class AuthorizerBase(ABC):
    @abstractmethod
    async def sign_request(self, request: AuthorizedRequestBase, service_public_key: Optional[Ed25519PublicKey]) -> None:
        ...

    @abstractmethod
    async def validate_request(self, request: AuthorizedRequestBase) -> bool:
        ...

    @abstractmethod
    async def sign_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> None:
        ...

    @abstractmethod
    async def validate_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> bool:
        ...


class TokenAuthorizerBase(AuthorizerBase):
    """
    Implements the authorization protocol for a moderated Hivemind network.
    See https://github.com/learning-at-home/hivemind/issues/253
    """

    def __init__(self, local_private_key: Optional[Ed25519PrivateKey] = None):
        if local_private_key is None:
            local_private_key = Ed25519PrivateKey.process_wide()
        self._local_private_key = local_private_key
        self._local_public_key = local_private_key.get_public_key()

        self._local_access_token = None
        self._refresh_lock = asyncio.Lock()

        self._recent_nonces = TimedStorage()

    @abstractmethod
    async def get_token(self) -> AccessToken:
        ...

    @abstractmethod
    def is_token_valid(self, access_token: AccessToken) -> bool:
        ...

    @abstractmethod
    def does_token_need_refreshing(self, access_token: AccessToken) -> bool:
        ...

    async def refresh_token_if_needed(self) -> None:
        if self._local_access_token is None or self.does_token_need_refreshing(self._local_access_token):
            async with self._refresh_lock:
                if self._local_access_token is None or self.does_token_need_refreshing(self._local_access_token):
                    self._local_access_token = await self.get_token()
                    assert self.is_token_valid(self._local_access_token)

    @property
    def local_public_key(self) -> Ed25519PublicKey:
        return self._local_public_key

    async def sign_request(self, request: AuthorizedRequestBase, service_public_key: Optional[Ed25519PublicKey]) -> None:
        await self.refresh_token_if_needed()
        auth = request.auth

        auth.client_access_token.CopyFrom(self._local_access_token)

        if service_public_key is not None:
            auth.service_public_key = service_public_key.to_bytes()
        auth.time = get_dht_time()
        auth.nonce = secrets.token_bytes(8)

        assert auth.signature == b""
        auth.signature = self._local_private_key.sign(request.SerializeToString())

    _MAX_CLIENT_SERVICER_TIME_DIFF = timedelta(minutes=1)

    async def validate_request(self, request: AuthorizedRequestBase) -> bool:
        await self.refresh_token_if_needed()
        auth = request.auth

        if not self.is_token_valid(auth.client_access_token):
            logger.debug("Client failed to prove that it (still) has access to the network")
            return False

        client_public_key = Ed25519PublicKey.from_bytes(auth.client_access_token.public_key)
        signature = auth.signature
        auth.signature = b""
        if not client_public_key.verify(request.SerializeToString(), signature):
            logger.debug("Request has invalid signature")
            return False

        if auth.service_public_key and auth.service_public_key != self._local_public_key.to_bytes():
            logger.debug("Request is generated for a peer with another public key")
            return False

        with self._recent_nonces.freeze():
            current_time = get_dht_time()
            if abs(auth.time - current_time) > self._MAX_CLIENT_SERVICER_TIME_DIFF.total_seconds():
                logger.debug("Clocks are not synchronized or a previous request is replayed again")
                return False
            if auth.nonce in self._recent_nonces:
                logger.debug("Previous request is replayed again")
                return False

        self._recent_nonces.store(
            auth.nonce, None, current_time + self._MAX_CLIENT_SERVICER_TIME_DIFF.total_seconds() * 3
        )
        return True

    async def sign_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> None:
        await self.refresh_token_if_needed()
        auth = response.auth

        auth.service_access_token.CopyFrom(self._local_access_token)
        auth.nonce = request.auth.nonce

        assert auth.signature == b""
        auth.signature = self._local_private_key.sign(response.SerializeToString())

    async def validate_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> bool:
        await self.refresh_token_if_needed()
        auth = response.auth

        if not self.is_token_valid(auth.service_access_token):
            logger.debug("Service failed to prove that it (still) has access to the network")
            return False

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

class POSAuthorizer(AuthorizerBase):
    """
    Implements a proof-of-stake authorization protocol using Ed25519 keys
    Checks the Hypertensor network for nodes ``peer_id`` is staked.
    The ``peer_id`` is retrieved using the Ed25519 public key
    """
    def __init__(self, local_private_key: Ed25519PrivateKey):
        super().__init__()

        self._local_private_key = local_private_key
        self._local_public_key = local_private_key.get_public_key()

    async def get_token(self) -> AccessToken:
        # Uses the built in Hivemind ``AccessToken`` format
        token = AccessToken(
            username='',
            public_key=self._local_public_key.to_bytes(),
            expiration_time=str(datetime.now(timezone.utc) + timedelta(minutes=1)),
        )
        token.signature = self._local_private_key.sign(self._token_to_bytes(token))
        return token

    @staticmethod
    def _token_to_bytes(access_token: AccessToken) -> bytes:
        return f"{access_token.username} {access_token.public_key} {access_token.expiration_time}".encode()

    async def sign_request(self, request: AuthorizedRequestBase, service_public_key: Optional[Ed25519PublicKey]) -> None:
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
        auth = request.auth

        # Get public key of signer
        try:
            client_public_key = Ed25519PublicKey.from_bytes(auth.client_access_token.public_key)
        except:
            return False

        signature = auth.signature
        auth.signature = b""
        # Verify signature of the request from signer
        if not client_public_key.verify(request.SerializeToString(), signature):
            logger.debug("Request has invalid signature")
            return False

        if auth.service_public_key and auth.service_public_key != self._local_public_key.to_bytes():
            logger.debug("Request is generated for a peer with another public key")
            return False

        # TODO: Add ``last_updated`` mapping to avoid over-checking POS
        try:
            encoded_public_key = crypto_pb2.PublicKey(
                key_type=crypto_pb2.Ed25519,
                data=client_public_key.to_raw_bytes(),
            ).SerializeToString()

            # For Ed25519
            encoded_public_key = b"\x00$" + encoded_public_key

            peer_id = PeerID(encoded_public_key)

            # TODO: Check proof-of-stake
            # Check if subnet node is >=registered classification
            # on-chain logic only allows being a subnet if staked
            # so we only check if they're an acitivated node
            proof_of_stake = True

            if not proof_of_stake:
                return False

            return True
        except Exception as e:
            logger.debug("Proof of stake failed", exc_info=True)
            return False

        return True

    async def sign_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> None:
        auth = response.auth

        local_access_token = await self.get_token()
        auth.service_access_token.CopyFrom(local_access_token)

        # auth.service_access_token.CopyFrom(self._local_public_key)
        auth.nonce = request.auth.nonce

        assert auth.signature == b""
        auth.signature = self._local_private_key.sign(response.SerializeToString())

    async def validate_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> bool:
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

class POSAuthorizerLive(AuthorizerBase):
    """
    Implements a proof-of-stake authorization protocol using Ed25519 keys
    Checks the Hypertensor network for nodes ``peer_id`` is staked.
    The ``peer_id`` is retrieved using the Ed25519 public key
    """
    def __init__(
        self, 
        local_private_key: Ed25519PrivateKey, 
        subnet_id: int, 
        interface: SubstrateInterface
    ):
        super().__init__()

        self._local_private_key = local_private_key
        self._local_public_key = local_private_key.get_public_key()
        self.subnet_id = subnet_id
        self.interface = interface

        self.peer_id_to_last_update: Dict[PeerID, int] = dict()
        self.pos_interim = 60

        """
        REMOVE THIS 
        Until all DHT requests are passed through from the originating DHT initialization.
        Otherwise, when entering the DHT, this will always get called with no way to stop it
        because it's a fresh class
        """
        # 
        # """
        # Ensure self is staked
        # """
        # try:
        #     proof_of_stake = self.proof_of_stake(self._local_public_key)
        #     assert proof_of_stake is True, f"Invalid proof-of-stake for subnet ID {self.subnet_id}" 
        # except Exception as e:
        #     logger.error(e, exc_info=True)


    async def get_token(self) -> AccessToken:
        # Uses the built in Hivemind ``AccessToken`` format
        token = AccessToken(
            username='',
            public_key=self._local_public_key.to_bytes(),
            expiration_time=str(datetime.now(timezone.utc) + timedelta(minutes=1)),
        )
        token.signature = self._local_private_key.sign(self._token_to_bytes(token))
        return token

    @staticmethod
    def _token_to_bytes(access_token: AccessToken) -> bytes:
        return f"{access_token.username} {access_token.public_key} {access_token.expiration_time}".encode()

    async def sign_request(self, request: AuthorizedRequestBase, service_public_key: Optional[Ed25519PublicKey]) -> None:
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
        auth = request.auth

        # Get public key of signer
        try:
            client_public_key = Ed25519PublicKey.from_bytes(auth.client_access_token.public_key)
        except:
            return False

        signature = auth.signature
        auth.signature = b""
        # Verify signature of the request from signer
        if not client_public_key.verify(request.SerializeToString(), signature):
            logger.debug("Request has invalid signature")
            return False

        if auth.service_public_key and auth.service_public_key != self._local_public_key.to_bytes():
            logger.debug("Request is generated for a peer with another public key")
            return False

        # Verify proof of stake
        try:
            proof_of_stake = self.proof_of_stake(client_public_key)
            return proof_of_stake
        except Exception as e:
            logger.debug("Proof of stake failed", exc_info=True)
            return False

    async def sign_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> None:
        auth = response.auth

        local_access_token = await self.get_token()
        auth.service_access_token.CopyFrom(local_access_token)

        # auth.service_access_token.CopyFrom(self._local_public_key)
        auth.nonce = request.auth.nonce

        assert auth.signature == b""
        auth.signature = self._local_private_key.sign(response.SerializeToString())

    async def validate_response(self, response: AuthorizedResponseBase, request: AuthorizedRequestBase) -> bool:
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

    def add_or_update_peer_id(self, peer_id: PeerID):
        timestamp = get_dht_time()
        self.peer_id_to_last_update[peer_id] = timestamp

    def get_peer_id_last_update(self, peer_id: PeerID) -> int:
        if peer_id not in self.peer_id_to_last_update:
            return 0
        
        return self.peer_id_to_last_update[peer_id]

    def proof_of_stake(self, public_key: Ed25519PublicKey) -> bool:        
        peer_id = self.get_peer_id(public_key)
        last_update = self.get_peer_id_last_update(peer_id)

        timestamp = get_dht_time()

        if last_update != 0 and timestamp - last_update < self.pos_interim:
            return True

        self.add_or_update_peer_id(peer_id)
        peer_id_vec = self.to_vec_u8(peer_id.to_base58())
        proof_of_stake = self.is_staked(peer_id_vec)

        return proof_of_stake

    def get_peer_id(self, public_key: Ed25519PublicKey) -> PeerID:
        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.Ed25519,
            data=public_key.to_raw_bytes(),
        ).SerializeToString()

        encoded_public_key = b"\x00$" + encoded_public_key

        peer_id = PeerID(encoded_public_key)

        return peer_id
    
    def to_vec_u8(self, string):
        return [ord(char) for char in string]

    def is_staked(self, peer_id_vector) -> bool:
        result = is_subnet_node_by_peer_id(
            self.interface,
            self.subnet_id,
            peer_id_vector
        )

        if "result" not in result:
            return False
                
        # must be True or False
        if result["result"] is not True and result["result"] is not False:
            return False

        return result["result"]

    @property
    def local_public_key(self) -> Ed25519PublicKey:
        return self._local_public_key

class AuthRole(Enum):
    CLIENT = 0
    SERVICER = 1


class AuthRPCWrapper:
    def __init__(
        self,
        stub,
        role: AuthRole,
        authorizer: Optional[AuthorizerBase],
        service_public_key: Optional[Ed25519PublicKey] = None,
    ):
        self._stub = stub
        self._role = role
        self._authorizer = authorizer
        self._service_public_key = service_public_key

    def __getattribute__(self, name: str):
        if not name.startswith("rpc_"):
            return object.__getattribute__(self, name)

        method = getattr(self._stub, name)

        @functools.wraps(method)
        async def wrapped_rpc(request: AuthorizedRequestBase, *args, **kwargs):
            if self._authorizer is not None:
                if self._role == AuthRole.CLIENT:
                    await self._authorizer.sign_request(request, self._service_public_key)
                elif self._role == AuthRole.SERVICER:
                    if not await self._authorizer.validate_request(request):
                        return None

            response = await method(request, *args, **kwargs)

            if self._authorizer is not None:
                if self._role == AuthRole.SERVICER:
                    await self._authorizer.sign_response(response, request)
                elif self._role == AuthRole.CLIENT:
                    if not await self._authorizer.validate_response(response, request):
                        return None

            return response

        return wrapped_rpc
