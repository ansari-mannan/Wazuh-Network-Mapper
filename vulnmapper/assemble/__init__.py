"""Merge endpoints + network discovery into one unified graph document.

Produces ``{nodes, edges, metadata}`` keyed by ``node_id``, stamped with
``discovery_order`` / ``parent_id`` so a frontend can replay the finished graph
as a topology growing from the seed, with endpoints sprouting off their parent
switch. See :mod:`merge`.
"""
