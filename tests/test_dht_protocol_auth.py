import asyncio
import hashlib
import multiprocessing as mp
import random
import signal
from typing import List, Optional, Sequence, Tuple

import multihash
import pytest

import hivemind
from hivemind import P2P, PeerID, get_dht_time, get_logger
from hivemind.dht import DHTID
from hivemind.dht.protocol import DHTProtocol
from hivemind.dht.storage import DictionaryDHTValue
from hivemind.p2p.multiaddr import Multiaddr
from hivemind.utils.auth import AuthorizedRequestBase, AuthorizedResponseBase, AuthorizerBase
from hivemind.utils.crypto import RSAPrivateKey, RSAPublicKey
from hivemind.proto import crypto_pb2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from test_auth import MockAuthorizer2

logger = get_logger(__name__)

# pytest tests/test_dht_protocol_auth.py -rP

def maddrs_to_peer_ids(maddrs: List[Multiaddr]) -> List[PeerID]:
    return list({PeerID.from_base58(maddr["p2p"]) for maddr in maddrs})


def run_protocol_listener(
    dhtid: DHTID, maddr_conn: mp.connection.Connection, initial_peers: Sequence[Multiaddr], key: int
) -> None:
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

    with open(f"tests/private_key_{key}.key", "wb") as f:
        f.write(protobuf.SerializeToString())

    with open(f"tests/private_key_{key}.key", "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        private_key = serialization.load_der_private_key(key_data, password=None)
        rsa_private_key = RSAPrivateKey(private_key=private_key)
        rsa_public_key = rsa_private_key.get_public_key()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        p2p = loop.run_until_complete(P2P.create(initial_peers=initial_peers, identity_path=f"tests/private_key_{key}.key"))
        visible_maddrs = loop.run_until_complete(p2p.get_visible_maddrs())

        protocol = loop.run_until_complete(
            DHTProtocol.create(
                p2p, 
                dhtid, 
                bucket_size=20, 
                depth_modulo=5, 
                num_replicas=3, 
                wait_timeout=5,
                authorizer=MockAuthorizer2(rsa_private_key)
            )
        )

        print(f"peer-{key} node id is: ", protocol.node_id)
        print(f"peer-{key} peer id is: ", p2p.peer_id)
        print(f"peer-{key} public key is: ", rsa_public_key.to_bytes())

        logger.info(f"Started peer id={protocol.node_id} visible_maddrs={visible_maddrs}")

        for peer_id in maddrs_to_peer_ids(initial_peers):
            loop.run_until_complete(protocol.call_ping(peer_id))

        maddr_conn.send((p2p.peer_id, visible_maddrs))

        async def shutdown():
            await p2p.shutdown()
            logger.info(f"Finished peer id={protocol.node_id} maddrs={visible_maddrs}")
            loop.stop()

        loop.add_signal_handler(signal.SIGTERM, lambda: loop.create_task(shutdown()))
        loop.run_forever()


def launch_protocol_listener(
    key: int,
    initial_peers: Sequence[Multiaddr] = (),
) -> Tuple[DHTID, mp.Process, PeerID, List[Multiaddr]]:
    remote_conn, local_conn = mp.Pipe()
    dht_id = DHTID.generate()
    process = mp.Process(target=run_protocol_listener, args=(dht_id, remote_conn, initial_peers, key), daemon=True)
    process.start()
    peer_id, visible_maddrs = local_conn.recv()

    return dht_id, process, peer_id, visible_maddrs


# pytest tests/test_dht_protocol_auth.py::test_dht_protocol -rP

@pytest.mark.forked
@pytest.mark.asyncio
async def test_dht_protocol():
    peer1_node_id, peer1_proc, peer1_id, peer1_maddrs = launch_protocol_listener(1)
    peer2_node_id, peer2_proc, peer2_id, _ = launch_protocol_listener(2, initial_peers=peer1_maddrs)

    for client_mode in [True, False]:  # note: order matters, this test assumes that first run uses client mode
        peer_id = DHTID.generate()
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

        with open(f"tests/private_key_client-{client_mode}.key", "wb") as f:
            f.write(protobuf.SerializeToString())

        with open(f"tests/private_key_client-{client_mode}.key", "rb") as f:
            data = f.read()
            key_data = crypto_pb2.PrivateKey.FromString(data).data
            private_key = serialization.load_der_private_key(key_data, password=None)
            rsa_private_key = RSAPrivateKey(private_key=private_key)
            rsa_public_key = rsa_private_key.get_public_key()

            p2p = await P2P.create(initial_peers=peer1_maddrs, identity_path=f"tests/private_key_client-{client_mode}.key")
            protocol = await DHTProtocol.create(
                p2p, 
                peer_id, 
                bucket_size=20, 
                depth_modulo=5, 
                wait_timeout=5, 
                num_replicas=3, 
                client_mode=client_mode,
                authorizer=MockAuthorizer2(rsa_private_key)
            )
            logger.info(f"Self id={protocol.node_id}")

            print(f"peer-{client_mode} node id is: ", protocol.node_id)
            print(f"peer-{client_mode} peer id is: ", p2p.peer_id)
            print(f"peer-{client_mode} public key is: ", rsa_public_key.to_bytes())


            # with open(f"tests/private_key_{1}.key", "rb") as f:
            #     peer1_data = f.read()
            #     peer1_key_data = crypto_pb2.PrivateKey.FromString(peer1_data).data
            #     peer1_private_key = serialization.load_der_private_key(peer1_key_data, password=None)
            #     peer1_rsa_private_key = RSAPrivateKey(private_key=peer1_private_key)
            #     peer1_rsa_public_key = peer1_rsa_private_key.get_public_key()

            #     assert peer1_node_id == await protocol.call_ping_with_pubkey(peer1_id, peer1_rsa_public_key)

            assert peer1_node_id == await protocol.call_ping(peer1_id)

            if not client_mode:
                await p2p.shutdown()

    peer1_proc.terminate()
    peer2_proc.terminate()

# pytest tests/test_dht_protocol_auth.py::test_dht_protocol_invalid -rP

@pytest.mark.forked
@pytest.mark.asyncio
async def test_dht_protocol_invalid():
    peer1_node_id, peer1_proc, peer1_id, peer1_maddrs = launch_protocol_listener(1)
    peer2_node_id, peer2_proc, peer2_id, _ = launch_protocol_listener(2, initial_peers=peer1_maddrs)

    for client_mode in [True, False]:  # note: order matters, this test assumes that first run uses client mode
        peer_id = DHTID.generate()
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

        with open(f"tests/private_key_client-{client_mode}.key", "wb") as f:
            f.write(protobuf.SerializeToString())

        with open(f"tests/private_key_client-{client_mode}.key", "rb") as f:
            data = f.read()
            key_data = crypto_pb2.PrivateKey.FromString(data).data
            private_key = serialization.load_der_private_key(key_data, password=None)
            rsa_private_key = RSAPrivateKey(private_key=private_key)
            rsa_public_key = rsa_private_key.get_public_key()

            p2p = await P2P.create(initial_peers=peer1_maddrs, identity_path=f"tests/private_key_client-{client_mode}.key")
            protocol = await DHTProtocol.create(
                p2p, 
                peer_id, 
                bucket_size=20, 
                depth_modulo=5, 
                wait_timeout=5, 
                num_replicas=3, 
                client_mode=client_mode,
                authorizer=MockAuthorizer2(rsa_private_key)
            )
            logger.info(f"Self id={protocol.node_id}")

            print(f"peer-{client_mode} node id is: ", protocol.node_id)
            print(f"peer-{client_mode} peer id is: ", p2p.peer_id)
            print(f"peer-{client_mode} public key is: ", rsa_public_key.to_bytes())

            # with open(f"tests/private_key_{1}.key", "rb") as f:
            #     peer1_data = f.read()
            #     peer1_key_data = crypto_pb2.PrivateKey.FromString(peer1_data).data
            #     peer1_private_key = serialization.load_der_private_key(peer1_key_data, password=None)
            #     peer1_rsa_private_key = RSAPrivateKey(private_key=peer1_private_key)
            #     peer1_rsa_public_key = peer1_rsa_private_key.get_public_key()

            #     assert peer1_node_id == await protocol.call_ping_with_pubkey(peer1_id, peer1_rsa_public_key)

            assert not peer1_node_id == await protocol.call_ping(peer2_id)

            if not client_mode:
                await p2p.shutdown()

    peer1_proc.terminate()
    peer2_proc.terminate()

@pytest.mark.forked
@pytest.mark.asyncio
async def test_dht_protocol_no_auth_err():
    peer1_node_id, peer1_proc, peer1_id, peer1_maddrs = launch_protocol_listener(1)
    peer2_node_id, peer2_proc, peer2_id, _ = launch_protocol_listener(2, initial_peers=peer1_maddrs)

    for client_mode in [True, False]:  # note: order matters, this test assumes that first run uses client mode
        peer_id = DHTID.generate()
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

        with open(f"tests/private_key_client-{client_mode}.key", "wb") as f:
            f.write(protobuf.SerializeToString())

        with open(f"tests/private_key_client-{client_mode}.key", "rb") as f:
            data = f.read()
            key_data = crypto_pb2.PrivateKey.FromString(data).data
            private_key = serialization.load_der_private_key(key_data, password=None)
            rsa_private_key = RSAPrivateKey(private_key=private_key)
            rsa_public_key = rsa_private_key.get_public_key()

            p2p = await P2P.create(initial_peers=peer1_maddrs, identity_path=f"tests/private_key_client-{client_mode}.key")
            protocol = await DHTProtocol.create(
                p2p, 
                peer_id, 
                bucket_size=20, 
                depth_modulo=5, 
                wait_timeout=5, 
                num_replicas=3, 
                client_mode=client_mode,
            )
            logger.info(f"Self id={protocol.node_id}")

            assert peer1_node_id != await protocol.call_ping(peer1_id)

            if not client_mode:
                await p2p.shutdown()

    peer1_proc.terminate()
    peer2_proc.terminate()

# @pytest.mark.forked
# @pytest.mark.asyncio
# async def test_empty_table():
#     """Test RPC methods with empty routing table"""
#     peer_id, peer_proc, peer_peer_id, peer_maddrs = launch_protocol_listener(0)

#     p2p = await P2P.create(initial_peers=peer_maddrs)
#     protocol = await DHTProtocol.create(
#         p2p, DHTID.generate(), bucket_size=20, depth_modulo=5, wait_timeout=5, num_replicas=3, client_mode=True
#     )

#     key, value, expiration = DHTID.generate(), [random.random(), {"ololo": "pyshpysh"}], get_dht_time() + 1e3

#     empty_item, nodes_found = (await protocol.call_find(peer_peer_id, [key]))[key]
#     assert empty_item is None and len(nodes_found) == 0
#     assert all(await protocol.call_store(peer_peer_id, [key], [hivemind.MSGPackSerializer.dumps(value)], expiration))

#     (recv_value_bytes, recv_expiration), nodes_found = (await protocol.call_find(peer_peer_id, [key]))[key]
#     recv_value = hivemind.MSGPackSerializer.loads(recv_value_bytes)
#     assert len(nodes_found) == 0
#     assert recv_value == value and recv_expiration == expiration

#     assert peer_id == await protocol.call_ping(peer_peer_id)
#     assert not await protocol.call_ping(PeerID.from_base58("fakeid"))
#     peer_proc.terminate()