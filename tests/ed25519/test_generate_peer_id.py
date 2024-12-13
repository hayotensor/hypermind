from hivemind.p2p.p2p_daemon import P2P
import pytest

import os 
import asyncio
import tempfile
from hivemind.utils.logging import get_logger

logger = get_logger(__name__)

# pytest tests/ed25519/test_generate_peer_id.py -rP

@pytest.mark.asyncio
async def test_identity():
    with tempfile.TemporaryDirectory() as tempdir:
        id1_path = os.path.join(tempdir, "id1")
        id2_path = os.path.join(tempdir, "id2")
        p2ps = await asyncio.gather(*[P2P.create(identity_path=path) for path in [None, None, id1_path, id2_path]])

        # We create the second daemon with id2 separately
        # to avoid a race condition while saving a newly generated identity
        p2ps.append(await P2P.create(identity_path=id2_path))

        # Using the same identity (if any) should lead to the same peer ID
        assert p2ps[-2].peer_id == p2ps[-1].peer_id

        # The rest of peer IDs should be different
        peer_ids = {instance.peer_id for instance in p2ps}
        assert len(peer_ids) == 4

        for instance in p2ps:
            await instance.shutdown()

    with pytest.raises(FileNotFoundError, match=r"The directory.+does not exist"):
        P2P.generate_identity(id1_path)

