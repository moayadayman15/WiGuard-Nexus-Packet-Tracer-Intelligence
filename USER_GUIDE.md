[project]
name = "wiguard-nexus"
version = "5.16.1"
description = "Wireless and wired policy evidence intelligence platform"
requires-python = ">=3.10"
dependencies = [
  "Flask>=3.0,<4.0",
  "Werkzeug>=3.0,<4.0",
  "defusedxml>=0.7,<1.0",
  "Jinja2>=3.1,<4.0",
  "reportlab>=4.0,<5.0",
  "networkx>=3.2,<4.0",
  "textfsm>=1.1,<2.0",
  "ntc-templates>=4.0,<8.0",
  "scapy>=2.5,<3.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0,<10.0", "pytest-cov>=5.0,<7.0", "ruff>=0.6.0", "bandit>=1.7.0", "pip-audit>=2.7.0"]
network = ["pybatfish>=2024.1.0", "netmiko>=4.3,<5.0", "napalm>=5.0,<6.0", "nornir>=3.4,<4.0"]
ai = ["ollama>=0.4.0", "sentence-transformers>=3.0.0", "chromadb>=0.5.0", "faiss-cpu>=1.8.0", "scikit-learn>=1.4.0"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
addopts = "-q --assert=plain -p no:ddtrace -p no:pytest_jsonreport -p no:faker -p no:cov -p no:metadata -p no:anyio -p no:asyncio"
