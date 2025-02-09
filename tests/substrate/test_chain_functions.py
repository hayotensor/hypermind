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

  peers = bytes(peers['result'])

  as_bytes = bytes(peers)
  as_scale_bytes = scalecodec.ScaleBytes(as_bytes)
  obj = RuntimeConfiguration().create_scale_object("BTreeMap<Vec<u8>,bool>", data=as_scale_bytes)
  obj.decode()
  print(obj.value)