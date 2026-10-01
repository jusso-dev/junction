# Service endpoint variables

`junction describe <operation> --json` includes `endpoint_template` when the
upstream definition declares a variable service URL. Its `variables` map lists
defaults and any allowed `choices`.

Cloud context files can supply operator bindings:

```json
"endpoint_variables": {
  "region": "east"
}
```

Bindings override declared defaults. Azure Swagger host variables without a
default require a binding. OpenAPI server variables require a string default in
the source definition, as specified by the
[OpenAPI Server Variable Object](https://spec.openapis.org/oas/v3.0.3.html#server-variable-object).
Missing bindings, unknown names, and values outside declared choices fail before
credential acquisition.

The resulting origin must match the configured service. For a service-specific
data-plane host, configure its endpoint and token audience explicitly in a custom
cloud context. Choosing a region does not automatically authorize a different
service origin. Set host variables in the trusted context file; operation input
parameters cannot change the service host.

Junction currently uses the first declared server. Relative server URLs and
selection among multiple server entries remain unsupported.
