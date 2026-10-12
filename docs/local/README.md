# Local development and evaluation

This section is separate from the customer Azure deployment path. It applies
only when running, testing, demonstrating, or replaying Vulnerability View on a
workstation.

Do not use local instructions to deploy or operate the hosted customer
application. For Azure deployment and normal operations, return to the
[project README](../../README.md) and use the interactive deployment menu.

## Choose the local task

| Local task | Guide |
|---|---|
| Evaluate the dashboard with local datasets | [Local evaluation and datasets](../local-evaluation.md) |
| Develop, test, or demonstrate the application | [Development, demonstration, and source control](../development.md) |
| Collect and replay an authorized sample | [Collect and replay a sample](../sample-replay.md) |
| Look up local-only commands | [Command reference](../command-reference.md) |

Local processes may use workstation credentials or local generated files.
Deployed Function and Web App resources use their managed identities and do not
depend on a workstation remaining signed in.

Local cleanup never authorizes deletion of Azure Storage history. Retained
`raw/`, `curated/`, and `runs/` paths remain protected and append-only.
