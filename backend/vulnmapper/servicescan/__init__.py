"""Optional service scan of unmanaged hosts (nmap -sV).

Active: it connects to the hosts. Off by default, confined to this package,
and only ever aimed at the unmanaged hosts the scan already discovered. See
:mod:`vulnmapper.servicescan.stage` for the stage and its bounds.
"""
