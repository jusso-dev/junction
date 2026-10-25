# Essential Eight coverage

How `junction check` maps to the ASD Essential Eight Maturity Model. The matrix is generated from
the checks' framework tags (`junction check docs`) and a test fails if it is stale.

- **Requirements** are the ISM controls ASD tags with Essential Eight maturity levels. They are synced
  one way from crownguard (`scripts/sync-frameworks.sh`); the strategy each requirement sits under is
  Junction's mapping in `scripts/sync-frameworks.py`.
- **Automated** checks read Microsoft APIs. **Manual** checks are answered by a person with
  `junction check attest` and expire.
- **Gaps** are requirements no check is tagged with. Many are outside what Microsoft 365 APIs can
  show (for example application control on servers, or patching third-party applications without
  Defender Vulnerability Management), and need other evidence.

The maturity estimate in HTML and Markdown reports uses the lowest level fully met per strategy: a
level counts as met only when at least one check is tagged at that level and every check tagged at or
below it passed. It is an **estimate, not an assessment**: the Essential Eight was designed for
Windows-based networks, many requirements need evidence no API exposes, and a formal assessment
follows ASD's Essential Eight Assessment Process Guide.

<!-- generated:coverage:start (junction check docs) -->
<!-- generated:coverage:end -->
