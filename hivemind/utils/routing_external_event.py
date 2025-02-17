"""An external events class that inherits a routing table

Can be used to add/remove peers from the routing table based on external events, such as events that come from
an the Hypertensor blockchain

"""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from hivemind.dht.routing import RoutingTable
from hivemind.p2p.p2p_daemon_bindings.datastructures import PeerID
from hivemind.utils.auth import POSAuthorizerLive
from hivemind.utils.logging import get_logger
from hivemind.substrate.chain_functions import are_subnet_nodes_by_peer_id
from hivemind.utils.timed_storage import get_dht_time
from hivemind.proto import crypto_pb2

from substrateinterface import SubstrateInterface
from scalecodec.base import ScaleBytes, RuntimeConfiguration

logger = get_logger(__name__)

class RoutingExternalEventBase(ABC):
    @abstractmethod
    async def external_background_job(self) -> None:
        ...

    @abstractmethod
    def add_routing_table(self, routing_table: RoutingTable, start: Optional[bool] = False) -> None:
        ...

    @abstractmethod
    async def shutdown(self):
        ...

class POSExternalEventBase(RoutingExternalEventBase):
    def __init__(
        self,
        pos_auth: POSAuthorizerLive,
        start: Optional[bool] = False,
    ):
        super().__init__()
        self.pos_auth = pos_auth
        self.subnet_id = pos_auth.subnet_id
        self.interface = pos_auth.interface
        self.interval = 600 # 10 minutes
        self.routing_table = None
        self.task = None

        if start:
            asyncio.run(self.start())

    async def external_background_job(self) -> None:
        while self.running and self.routing_table is not None:
            peer_ids: List[PeerID] = []
            timestamp = get_dht_time()

            # ensure everyone is always running this at the same time
            next_run = timestamp - (timestamp % self.interval) + self.interval

            # compile data for single rpc call
            for peer_id, node_id in self.routing_table.peer_id_to_uid.items():
                peer_ids.append(peer_id)

            if peer_ids:
                result = are_subnet_nodes_by_peer_id(
                    self.interface,
                    self.subnet_id,
                    peer_ids
                )

                # skip if no results
                if "result" in result:
                    result = result["result"]
                    data = self.decode_data(result)

                    if data:
                        self.handle_pos(data)

            await asyncio.sleep(next_run)

    def handle_pos(self, data):
        """
        Handle of removal of peers from routing table if not POS

        Args:
            data (tuple): BTreeMap<Vec<u8>,bool> as decoded tuple (peer_id, bool).
        """
        # Get POS nodes only
        pos = {peer_id: flag for peer_id, flag in data}

        for peer_id, node_id in self.routing_table.peer_id_to_uid.items():
            # Check if peer is in the POS data results
            if peer_id not in pos or not pos[peer_id]:
                # Remove peer from routing table
                logger.info(f"{peer_id} no longer staked, removing from routing table")
                self.pos_auth.del_peer_id(peer_id)

                if node_id is not None and node_id in self.routing_table:
                    del self.routing_table[node_id]

    def add_routing_table(self, routing_table: RoutingTable, start: Optional[bool] = False) -> None:
        self.routing_table = routing_table
        if start:
            asyncio.run(self.start())
            
    def decode_data(self, data):
        try:
            as_bytes = bytes(data)
            as_scale_bytes = ScaleBytes(as_bytes)
            obj = RuntimeConfiguration().create_scale_object("BTreeMap<Vec<u8>,bool>", data=as_scale_bytes)
            return obj.decode()
        except Exception as e:
            return None

    async def start(self):
        """Start the RPC query."""
        self.running = True
        self.task = await asyncio.create_task(self.external_background_job())  # Run as a background task

    async def shutdown(self):
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass