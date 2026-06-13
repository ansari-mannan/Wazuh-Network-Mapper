"""The Wazuh endpoint side of the pipeline.

Behavior-preserving refactor of the original two monolithic scripts
(``wazuh_agent_collector.py`` / NTM and ``wazuh_cvss_collector.py`` / APA) into
shared fetch -> normalize -> orchestrate layers:

  wazuh_client.py    HTTP fetch from the Manager API (collect stage)
  indexer_client.py  HTTP fetch from the Indexer (score stage)
  normalize.py       pure data-shaping: normalize_agent / parse_hit / enrich_agent
  collect.py         orchestration -> agents.json
  score.py           orchestration -> scored_agents.json

What each layer fetches and how it authenticates is unchanged; only the
structure (shared, layered, deduplicated) and the indexer join key
(``agent.id`` instead of the fragile ``agent.name``) are new.
"""
