"""
Originally taken from: https://github.com/opentensor/bittensor/blob/master/bittensor/core/chain_data/utils.py
Licence: MIT
Author: Yuma Rao
"""

from enum import Enum
import scalecodec
from dataclasses import dataclass
from scalecodec.base import RuntimeConfiguration, ScaleBytes
from typing import List, Dict, Optional, Any, Union
from scalecodec.type_registry import load_type_registry_preset
from scalecodec.utils.ss58 import ss58_encode

U16_MAX = 65535
U64_MAX = 18446744073709551615

def U16_NORMALIZED_FLOAT(x: int) -> float:
  return float(x) / float(U16_MAX)

def U64_NORMALIZED_FLOAT(x: int) -> float:
  return float(x) / float(U64_MAX)

custom_rpc_type_registry = {
  "types": {
    "SubnetNode": {
      "type": "struct",
      "type_mapping": [
        ["account_id", "AccountId"],
        ["hotkey", "AccountId"],
        ["peer_id", "Vec<u8>"],
        ["initialized", "u64"],
        ["classification", "SubnetNodeClassification"],
        ["a", "Vec<u8>"],
        ["b", "Vec<u8>"],
        ["c", "Vec<u8>"],
      ],
    },
    "SubnetNodeClassification": {
      "type": "struct",
      "type_mapping": [
        ["class", "SubnetNodeClass"],
        ["start_epoch", "u64"],
      ],
    },
    "SubnetNodeClass": {
      "type": "enum",
      "value_list": [
        "Registered", 
        "Idle", 
        "Included", 
        "Submittable", 
        "Accountant"
      ],
    },
    "SubnetNodeClass": {
      "type": "BTreeMap",
      "value_list": [
        "Registered", 
        "Idle", 
        "Included", 
        "Submittable", 
        "Accountant"
      ],
    },
  }
}

class ChainDataType(Enum):
  """
  Enum for chain data types.
  """
  SubnetNode = 1

def from_scale_encoding(
    input: Union[List[int], bytes, ScaleBytes],
    type_name: ChainDataType,
    is_vec: bool = False,
    is_option: bool = False,
) -> Optional[Dict]:
    """
    Returns the decoded data from the SCALE encoded input.

    Args:
      input (Union[List[int], bytes, ScaleBytes]): The SCALE encoded input.
      type_name (ChainDataType): The ChainDataType enum.
      is_vec (bool): Whether the input is a Vec.
      is_option (bool): Whether the input is an Option.

    Returns:
      Optional[Dict]: The decoded data
    """
    
    type_string = type_name.name
    if is_option:
      type_string = f"Option<{type_string}>"
    if is_vec:
      type_string = f"Vec<{type_string}>"

    return from_scale_encoding_using_type_string(input, type_string)

def from_scale_encoding_using_type_string(
  input: Union[List[int], bytes, ScaleBytes], type_string: str
) -> Optional[Dict]:
  """
  Returns the decoded data from the SCALE encoded input using the type string.

  Args:
    input (Union[List[int], bytes, ScaleBytes]): The SCALE encoded input.
    type_string (str): The type string.

  Returns:
    Optional[Dict]: The decoded data
  """
  if isinstance(input, ScaleBytes):
    as_scale_bytes = input
  else:
    if isinstance(input, list) and all([isinstance(i, int) for i in input]):
      vec_u8 = input
      as_bytes = bytes(vec_u8)
    elif isinstance(input, bytes):
      as_bytes = input
    else:
      raise TypeError("input must be a List[int], bytes, or ScaleBytes")

    as_scale_bytes = scalecodec.ScaleBytes(as_bytes)

  rpc_runtime_config = RuntimeConfiguration()
  rpc_runtime_config.update_type_registry(load_type_registry_preset("legacy"))
  rpc_runtime_config.update_type_registry(custom_rpc_type_registry)

  obj = rpc_runtime_config.create_scale_object(type_string, data=as_scale_bytes)

  return obj.decode()

@dataclass
class SubnetNode:
  """
  Dataclass for model peer metadata.
  """

  account_id: str
  hotkey: str
  peer_id: str
  initialized: int
  classification: str
  a: str
  b: str
  c: str

  @classmethod
  def fix_decoded_values(cls, data_decoded: Any) -> "SubnetNode":
    """Fixes the values of the SubnetNode object."""
    data_decoded["account_id"] = ss58_encode(
      data_decoded["account_id"], 42
    )
    data_decoded["hotkey"] = data_decoded["hotkey"]
    data_decoded["peer_id"] = data_decoded["peer_id"]
    data_decoded["initialized"] = data_decoded["initialized"]
    data_decoded["classification"] = data_decoded["classification"]
    data_decoded["a"] = data_decoded["a"]
    data_decoded["b"] = data_decoded["b"]
    data_decoded["c"] = data_decoded["c"]

    return cls(**data_decoded)

  @classmethod
  def list_from_vec_u8(cls, vec_u8: List[int]) -> List["SubnetNode"]:
    """Returns a list of SubnetNode objects from a ``vec_u8``."""

    decoded_list = from_scale_encoding(
      vec_u8, ChainDataType.SubnetNode, is_vec=True
    )
    if decoded_list is None:
      return []

    decoded_list = [
      SubnetNode.fix_decoded_values(decoded) for decoded in decoded_list
    ]
    return decoded_list

  @staticmethod
  def _subnet_node_info_to_namespace(data) -> "SubnetNode":
    """
    Converts a SubnetNode object to a namespace.

    Args:
      rewards_data (SubnetNode): The SubnetNode object.

    Returns:
      SubnetNode: The SubnetNode object.
    """
    data = SubnetNode(**data)

    return data