from typing import List
from substrateinterface import SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException
from tenacity import retry, stop_after_attempt, wait_exponential

def is_subnet_node_by_peer_id(
  substrate: SubstrateInterface,
  subnet_id: int,
  peer_id: str
):
  @retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(4))
  def make_rpc_request():
    try:
      with substrate as _substrate:
        is_subnet_node = _substrate.rpc_request(
          method='network_isSubnetNodeByPeerId',
          params=[
            subnet_id,
            peer_id
          ]
        )
        return is_subnet_node
    except SubstrateRequestException as e:
      print("Failed to get rpc request: {}".format(e))

  return make_rpc_request()

def are_subnet_nodes_by_peer_id(
  substrate: SubstrateInterface,
  subnet_id: int,
  peer_ids: List[str]
):
  @retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(4))
  def make_rpc_request():
    try:
      with substrate as _substrate:
        is_subnet_nodes = _substrate.rpc_request(
          method='network_areSubnetNodesByPeerId',
          params=[
            subnet_id,
            peer_ids
          ]
        )
        return is_subnet_nodes
    except SubstrateRequestException as e:
      print("Failed to get rpc request: {}".format(e))

  return make_rpc_request()

def is_subnet_node_by_a_parameter(
  substrate: SubstrateInterface,
  subnet_id: int,
  a: str
):
  @retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(4))
  def make_rpc_request():
    try:
      with substrate as _substrate:
        is_subnet_node = _substrate.rpc_request(
          method='network_isSubnetNodeByA',
          params=[
            subnet_id,
            a
          ]
        )
        return is_subnet_node
    except SubstrateRequestException as e:
      print("Failed to get rpc request: {}".format(e))

  return make_rpc_request()
