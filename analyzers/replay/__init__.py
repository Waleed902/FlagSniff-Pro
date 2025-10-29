"""Interactive packet replay and modification engine.

This module provides tools for:
- Crafting custom packets from templates
- Replaying captured traffic with modifications
- Protocol fuzzing and security testing
- Stream injection and manipulation
"""

from .packet_crafter import (
    PacketTemplate,
    PacketCrafter,
    PacketReplayer,
    StreamInjector,
    craft_exploit_packet
)

from .fuzzer import (
    FuzzResult,
    ProtocolFuzzer,
    ProtocolStateFuzzer
)

__all__ = [
    # Packet crafting and replay
    'PacketTemplate',
    'PacketCrafter',
    'PacketReplayer',
    'StreamInjector',
    'craft_exploit_packet',
    
    # Fuzzing
    'FuzzResult',
    'ProtocolFuzzer',
    'ProtocolStateFuzzer',
]
