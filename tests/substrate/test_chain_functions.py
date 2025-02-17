from typing import Dict
import pytest
import scalecodec
from substrateinterface import SubstrateInterface
from scalecodec.base import RuntimeConfiguration, ScaleBytes
from scalecodec.type_registry import load_type_registry_preset

from hivemind.substrate.chain_functions import are_subnet_nodes_by_peer_id
from utils import RPC_URL

def get_peer_ids(count: int):
  peer_ids = []
  for i in range(0, count):
    peer_id = f"12D{i}KooWGFuUunX1AzAzjs3CgyqTXtPWX3AqRhJFbesGPGYHJQTP"
    peer_id_vec = to_vec_u8(peer_id)
    peer_ids.append(peer_id_vec)

  return peer_ids 

def to_vec_u8(string):
    """Get peer_id in vec<u8> for blockchain"""
    return [ord(char) for char in string]

# pytest tests/substrate/test_chain_functions.py::test_valid_request_and_response -rP

@pytest.mark.asyncio
async def test_valid_request_and_response():
  substrate = SubstrateInterface(url=RPC_URL)
  peer_ids = get_peer_ids(6)
  peers = are_subnet_nodes_by_peer_id(
    substrate,
    1,
    peer_ids
  )

  as_bytes = bytes(peers['result'])
  as_scale_bytes = ScaleBytes(as_bytes)
  obj = RuntimeConfiguration().create_scale_object("BTreeMap<Vec<u8>,bool>", data=as_scale_bytes)
  obj.decode()

  data = obj.value
  print(data)

  for peer_id, is_staked in data:
    print("peer_id ", peer_id)
    print("is_staked ", is_staked)

  peer_status = {peer_id: flag for peer_id, flag in data}
  print("peer_status ", peer_status)

  # simulate routing table
  peer_id_to_uid: Dict[str, str] = {
    '12D0KooWGFuUunX1AzAzjs3CgyqTXtPWX3AqRhJFbesGPGYHJQTP': 'DHT1',
    '12D2KooWGFuUunX1AzAzjs3CgyqTXtPWX3AqRhJFbesGPGYHJQTP': 'DHT2',
    '12D4KooWGFuUunX1AzAzjs3CgyqTXtPWX3AqRhJFbesGPGYHJQTP': 'DHT3',
    '12D6KooWGFuUunX1AzAzjs3CgyqTXtPWX3AqRhJFbesGPGYHJQTP': 'DHT4'  # False peer (remove from blockchain to test)
  }

  pos = {peer_id: flag for peer_id, flag in data}

  # iterate all nodes in the routing table and see if we should remove
  for peer_id, dht_id in peer_id_to_uid.items():
    # Check if peer is in the POS data results
    if peer_id not in pos or not pos[peer_id]:
      # Remove peer from routing table
      print(f"Removed Peer: {peer_id} DHTID: {dht_id}")
