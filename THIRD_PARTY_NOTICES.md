# Dependency and source notices

The application and tests use no PyPI dependency. Python and SQLite are supplied runtimes rather than redistributed binaries.

| Component | Version observed/required | License/source |
| --- | --- | --- |
| Python | Python 3.11; supplied Windows launcher selects 3.11.9 | [Python 3.11 license notices](https://docs.python.org/3.11/license.html), [3.11.9 release](https://www.python.org/downloads/release/python-3119/) |
| SQLite | Python-bundled; supplied runtime reports 3.45.1 | [SQLite public-domain notice](https://sqlite.org/copyright.html), [3.45.1 release](https://sqlite.org/releaselog/3_45_1.html) |
| Application and synthetic fixtures | Original project content | Repository MIT license |
| Optional Ollama server | Native /api/chat protocol target; no server or model installed/executed | [Ollama API documentation](https://docs.ollama.com/api/chat), [Ollama MIT license](https://github.com/ollama/ollama/blob/main/LICENSE); model licenses are separate |
| Future CI checkout | v7.0.1, commit 3d3c42e5aac5ba805825da76410c181273ba90b1 | [Official release](https://github.com/actions/checkout/releases/tag/v7.0.1), [MIT license](https://github.com/actions/checkout/blob/v7.0.1/LICENSE) |
| Future CI setup-python | v7.0.0, commit 5fda3b95a4ea91299a34e894583c3862153e4b97 | [Official release](https://github.com/actions/setup-python/releases/tag/v7.0.0), [MIT license](https://github.com/actions/setup-python/blob/v7.0.0/LICENSE) |

Action release/commit metadata was verified in primary sources on 2026-10-08
before authoring. These pins identify reviewed revisions, not a latest-version
claim. No action was downloaded/executed locally and no hosted workflow ran.
GitHub documents free standard hosted runners for public repositories in its
[Actions billing documentation](https://docs.github.com/en/billing/concepts/product-billing/github-actions);
private-account quotas are account-dependent.

The supplied patch versions identify the tested environment, not the latest available security patches. No third-party source, detector rules, model weights, or logs are bundled.

Primary motivation and prior art, reviewed 2026-10-08: [Databricks Agentic Security Engineering](https://www.databricks.com/company/careers/security/staff-security-software-engineer---agentic-security-engineering--7932280002), [Datadog Agentic Interfaces](https://careers.datadoghq.com/detail/7964141/), [Microsoft risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks), [MITRE T1078](https://attack.mitre.org/techniques/T1078/), [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), and [Sigma](https://github.com/SigmaHQ/sigma). These are attribution links, not employer endorsement or production/compliance claims. Sigma rules have their own DRL 1.1 license and are not copied here.
