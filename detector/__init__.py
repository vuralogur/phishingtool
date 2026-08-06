"""Phishing email detection / analysis tool (defensive).

Static, offline-first analysis of .eml files or raw email text.
Core analysis uses only the Python standard library; optional third-party
packages (tldextract, rich, dnspython, python-whois, requests) add polish
and online lookups, but the tool degrades gracefully without them.
"""

__version__ = "0.1.0"
