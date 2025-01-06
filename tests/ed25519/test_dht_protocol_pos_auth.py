import asyncio
import hashlib
import multiprocessing as mp
import random
import signal
from typing import List, Optional, Sequence, Tuple

import multihash
import pytest
from multiaddr import Multiaddr

import hivemind
from hivemind import P2P, PeerID, get_dht_time, get_logger
from hivemind.dht import DHTID
from hivemind.dht.protocol import DHTProtocol
from hivemind.dht.storage import DictionaryDHTValue
from cryptography.hazmat.primitives import serialization

from hivemind.utils.auth import POSAuthorizer, POSAuthorizerLive
from hivemind.utils.crypto import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from hivemind.proto import crypto_pb2

from substrateinterface import SubstrateInterface, Keypair, ExtrinsicReceipt
from substrateinterface.exceptions import SubstrateRequestException
from tenacity import retry, stop_after_attempt, wait_exponential

from hivemind.utils.substrate import is_subnet_node_by_peer_id

logger = get_logger(__name__)

RPC_URL = "ws://127.0.0.1:9944"

def maddrs_to_peer_ids(maddrs: List[Multiaddr]) -> List[PeerID]:
    return list({PeerID.from_base58(maddr["p2p"]) for maddr in maddrs})

def register_subnet_node(
  substrate: SubstrateInterface,
  keypair: Keypair,
  subnet_id: int,
  peer_id: str,
  stake_to_be_added: int,
  a: Optional[str] = None,
  b: Optional[str] = None,
  c: Optional[str] = None,
) -> ExtrinsicReceipt:
  """
  Add subnet validator as subnet subnet_node to blockchain storage

  :param substrate: interface to blockchain
  :param keypair: keypair of extrinsic caller. Must be a subnet_node in the subnet
  """

  # compose call
  call = substrate.compose_call(
    call_module='Network',
    call_function='register_subnet_node',
    call_params={
      'subnet_id': subnet_id,
      'peer_id': peer_id,
      'stake_to_be_added': stake_to_be_added,
      'a': a,
      'b': b,
      'c': c,
    }
  )

  # create signed extrinsic
  extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)

  @retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(4))
  def submit_extrinsic():
    try:
      receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
      return receipt
    except SubstrateRequestException as e:
      print("Failed to send: {}".format(e))

  return submit_extrinsic()

def run_register_subnet_node(key: int, peer_id: str):
    print("run_register_subnet_node")
    keypair = Keypair.create_from_uri(f"//{key}")
    print("keypair", keypair.ss58_address)
    try:
        receipt = register_subnet_node(
            SubstrateInterface(url=RPC_URL),
            keypair,
            1,
            peer_id,
            int(1000 * 1e18),
            None,
            None,
            None
        )
        assert receipt.is_success
    except Exception as e:
        print(f"Error running register_subnet_node: {e}")

def run_protocol_listener(
    dhtid: DHTID, maddr_conn: mp.connection.Connection, initial_peers: Sequence[Multiaddr], key: int
) -> None:
    print("run_protocol_listener")
    private_key = ed25519.Ed25519PrivateKey.generate()

    raw_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,  # DER format
        format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
        encryption_algorithm=serialization.NoEncryption()  # No encryption
    )

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    combined_key_bytes = raw_private_key + public_key

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

    with open(f"tests/ed25519/private_key_{key}.key", "wb") as f:
        f.write(protobuf.SerializeToString())

    with open(f"tests/ed25519/private_key_{key}.key", "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data
        raw_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
        private_key = Ed25519PrivateKey(private_key=raw_private_key)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        p2p = loop.run_until_complete(P2P.create(initial_peers=initial_peers))
        peer_id = p2p.peer_id
        print("peer_id", peer_id)
        
        # register subnet node
        run_register_subnet_node(key, peer_id.to_base58())

        visible_maddrs = loop.run_until_complete(p2p.get_visible_maddrs())

        protocol = loop.run_until_complete(
            DHTProtocol.create(
                p2p, 
                dhtid, 
                bucket_size=20, 
                depth_modulo=5, 
                num_replicas=3, 
                wait_timeout=5,
                authorizer=POSAuthorizerLive(private_key, 1, SubstrateInterface(url=RPC_URL))
                # authorizer=POSAuthorizer(private_key)
            )
        )

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
    print("launch_protocol_listener")
    remote_conn, local_conn = mp.Pipe()
    dht_id = DHTID.generate()
    process = mp.Process(target=run_protocol_listener, args=(dht_id, remote_conn, initial_peers, key), daemon=True)
    process.start()
    peer_id, visible_maddrs = local_conn.recv()

    return dht_id, process, peer_id, visible_maddrs

# pytest tests/ed25519/test_dht_protocol_pos_auth.py::test_dht_protocol_pos_auth -rP

@pytest.mark.forked
@pytest.mark.asyncio
async def test_dht_protocol_pos_auth():
    print("test_dht_protocol_pos_auth")
    peer1_node_id, peer1_proc, peer1_id, peer1_maddrs = launch_protocol_listener(1)
    peer2_node_id, peer2_proc, peer2_id, _ = launch_protocol_listener(2, initial_peers=peer1_maddrs)

    n = 50
    for client_mode in [True, False]:  # note: order matters, this test assumes that first run uses client mode
        peer_id = DHTID.generate()

        private_key = ed25519.Ed25519PrivateKey.generate()

        raw_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,  # DER format
            format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
            encryption_algorithm=serialization.NoEncryption()  # No encryption
        )

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        combined_key_bytes = raw_private_key + public_key

        protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

        with open(f"tests/ed25519/private_key_client-{client_mode}.key", "wb") as f:
            f.write(protobuf.SerializeToString())

        with open(f"tests/ed25519/private_key_client-{client_mode}.key", "rb") as f:
            data = f.read()
            key_data = crypto_pb2.PrivateKey.FromString(data).data
            raw_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
            private_key = Ed25519PrivateKey(private_key=raw_private_key)
            public_key = raw_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            p2p = await P2P.create(initial_peers=peer1_maddrs, identity_path=f"tests/private_key_client-{client_mode}.key")
            protocol = await DHTProtocol.create(
                p2p, 
                peer_id, 
                bucket_size=20, 
                depth_modulo=5, 
                wait_timeout=5, 
                num_replicas=3, 
                client_mode=client_mode,
                authorizer=POSAuthorizerLive(private_key, 1, SubstrateInterface(url=RPC_URL))
                # authorizer=POSAuthorizer(private_key)
            )
            logger.info(f"Self id={protocol.node_id}")

            print(f"peer-{client_mode} node id is: ", protocol.node_id)
            print(f"peer-{client_mode} peer id is: ", p2p.peer_id)
            print(f"peer-{client_mode} public key is: ", public_key)

            assert peer1_node_id == await protocol.call_ping(peer1_id)

            if not client_mode:
                await p2p.shutdown()

        n += 1

    peer1_proc.terminate()
    peer2_proc.terminate()



# pytest tests/ed25519/test_dht_protocol_pos_auth.py::test_pos_authorizer -rP

@pytest.mark.asyncio
async def test_pos_authorizer():
    print("run_pos_authorizer")
    private_key = ed25519.Ed25519PrivateKey.generate()

    raw_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,  # DER format
        format=serialization.PrivateFormat.Raw,  # PKCS8 standard format
        encryption_algorithm=serialization.NoEncryption()  # No encryption
    )

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    combined_key_bytes = raw_private_key + public_key

    protobuf = crypto_pb2.PrivateKey(key_type=crypto_pb2.KeyType.Ed25519, data=combined_key_bytes)

    with open(f"tests/ed25519/private_key_pos.key", "wb") as f:
        f.write(protobuf.SerializeToString())

    with open(f"tests/ed25519/private_key_pos.key", "rb") as f:
        data = f.read()
        key_data = crypto_pb2.PrivateKey.FromString(data).data

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
        ed25519_private_key = Ed25519PrivateKey(private_key=private_key)
        
        pubkey = ed25519_private_key.get_public_key()
        print("pubkey", pubkey)

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        encoded_public_key = crypto_pb2.PublicKey(
            key_type=crypto_pb2.Ed25519,
            data=public_key,
        ).SerializeToString()

        encoded_digest = b"\x00$" + encoded_public_key

        peer_id = PeerID(encoded_digest)

        # POSAuthorizer(ed25519_private_key)

    keypair = Keypair.create_from_uri(f"//{1}")
    try:
        receipt = register_subnet_node(
            SubstrateInterface(url=RPC_URL),
            keypair,
            1,
            peer_id.to_base58(),
            int(1000 * 1e18),
            None,
            None,
            None
        )
        assert receipt.is_success
    except Exception as e:
        print(f"Error running register_subnet_node: {e}")

    print("peer_id", peer_id.to_base58())
    peer_id_vec = [ord(char) for char in peer_id.to_base58()]

    print(peer_id_vec)

    proof_of_stake = is_subnet_node_by_peer_id(
        SubstrateInterface(url=RPC_URL),
        1,
        peer_id_vec
    )
    print("proof_of_stake", proof_of_stake)




    POSAuthorizerLive(ed25519_private_key, 1, SubstrateInterface(url=RPC_URL))

    # with open(f"tests/ed25519/private_key_pos.key", "rb") as f:
    #     data = f.read()
    #     key_data = crypto_pb2.PrivateKey.FromString(data).data
    #     raw_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data[:32])
    #     ed25519_private_key = Ed25519PrivateKey(private_key=raw_private_key)

    # POSAuthorizer(ed25519_private_key)