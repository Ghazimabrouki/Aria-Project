"""
OpenSOAR Pipeline Module.
Provides alert forwarding from Elasticsearch to OpenSOAR.
"""

from pipeline.sender import client, OpenSOARClient
from pipeline.poller import run_forwarder, poll_source
from pipeline.mappers import map_alert, MAPPERS

__all__ = [
    "client",
    "OpenSOARClient", 
    "run_forwarder",
    "poll_source",
    "map_alert",
    "MAPPERS",
]