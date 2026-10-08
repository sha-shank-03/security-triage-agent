# Dependency and source notices

The application and tests use no PyPI dependency. Python and SQLite are supplied runtimes rather than redistributed binaries.

| Component | Version observed/required | License/source |
| --- | --- | --- |
| Python | Python 3.11; supplied Windows launcher selects 3.11.9 | [Python 3.11 license notices](https://docs.python.org/3.11/license.html), [3.11.9 release](https://www.python.org/downloads/release/python-3119/) |
| SQLite | Python-bundled; supplied runtime reports 3.45.1 | [SQLite public-domain notice](https://sqlite.org/copyright.html), [3.45.1 release](https://sqlite.org/releaselog/3_45_1.html) |
| Application and synthetic fixtures | Original project content | Repository MIT license |
| Optional Ollama server | Native /api/chat protocol target; no server or model installed/executed | [Ollama API documentation](https://docs.ollama.com/api/chat), [Ollama MIT license](https://github.com/ollama/ollama/blob/main/LICENSE); model licenses are separate |

The supplied patch versions identify the tested environment, not the latest available security patches. No third-party source, detector rules, model weights, or logs are bundled.

Primary motivation and prior art, reviewed 2026-10-08: [Databricks Agentic Security Engineering](https://www.databricks.com/company/careers/security/staff-security-software-engineer---agentic-security-engineering--7932280002), [Datadog Agentic Interfaces](https://careers.datadoghq.com/detail/7964141/), [Microsoft risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks), [MITRE T1078](https://attack.mitre.org/techniques/T1078/), [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), and [Sigma](https://github.com/SigmaHQ/sigma). These are attribution links, not employer endorsement or production/compliance claims. Sigma rules have their own DRL 1.1 license and are not copied here.
