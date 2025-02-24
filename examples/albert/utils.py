from typing import Dict, List, Tuple

from pydantic.v1 import BaseModel, StrictFloat, confloat, conint

from hypermind.dht.crypto import RSASignatureValidator
from hypermind.dht.schema import BytesWithPublicKey, SchemaValidator
from hypermind.dht.validation import RecordValidatorBase
from hypermind.utils.logging import get_logger

logger = get_logger(__name__)


class LocalMetrics(BaseModel):
    step: conint(ge=0, strict=True)
    samples_per_second: confloat(ge=0.0, strict=True)
    samples_accumulated: conint(ge=0, strict=True)
    loss: StrictFloat
    mini_steps: conint(ge=0, strict=True)


class MetricSchema(BaseModel):
    metrics: Dict[BytesWithPublicKey, LocalMetrics]


def make_validators(run_id: str) -> Tuple[List[RecordValidatorBase], bytes]:
    signature_validator = RSASignatureValidator()
    validators = [SchemaValidator(MetricSchema, prefix=run_id), signature_validator]
    return validators, signature_validator.local_public_key
