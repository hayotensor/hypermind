"""
Compression strategies that reduce the network communication in .averaging, .optim and .moe
"""

from hypermind.compression.adaptive import PerTensorCompression, RoleAdaptiveCompression, SizeAdaptiveCompression
from hypermind.compression.base import CompressionBase, CompressionInfo, NoCompression, TensorRole
from hypermind.compression.floating import Float16Compression, ScaledFloat16Compression
from hypermind.compression.quantization import BlockwiseQuantization, Quantile8BitQuantization, Uniform8BitQuantization
from hypermind.compression.serialization import (
    deserialize_tensor_stream,
    deserialize_torch_tensor,
    serialize_torch_tensor,
)
