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

logger = get_logger(__name__)

class RoutingExternalEventBase(ABC):
    @abstractmethod
    async def external_background_job(self) -> None:
        ...

    @abstractmethod
    def add_routing_table(self, routing_table: RoutingTable) -> None:
        ...

class POSExternalEventBase(RoutingExternalEventBase):
    def __init__(
        self,
        pos_auth: POSAuthorizerLive,
        dht_protocol,
        start: Optional[bool] = False,
    ):
        super().__init__()
        self.pos_auth = pos_auth
        self.subnet_id = pos_auth.subnet_id
        self.interface = pos_auth.interface
        self.dht_protocol = dht_protocol
        self.pos_interim = 360
        self.routing_table = None

        if start:
            asyncio.run(self.start())

    async def external_background_job(self) -> None:
        while self.running and self.routing_table is not None:
            peer_ids: List[PeerID] = []
            timestamp = get_dht_time()
            # compile data for single rpc call
            for peer_id, last_update in self.pos_auth.peer_id_to_last_update.items():
                if timestamp - last_update > self.pos_interim:
                    peer_ids.append(peer_id)

            if peer_ids:
                result = are_subnet_nodes_by_peer_id(
                    self.interface,
                    self.subnet_id,
                    peer_ids
                )

                # skip if no results
                if "result" not in result:
                    continue

                result = result["result"]

            await asyncio.sleep(self.pos_interim)

    def add_routing_table(self, routing_table: RoutingTable) -> None:
        self.routing_table = routing_table

    async def start(self):
        """Start the RPC query."""
        self.running = True
        await asyncio.create_task(self.external_background_job())  # Run as a background task
