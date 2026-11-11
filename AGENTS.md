# Repository Rules

## Versioning

- Every change set must bump the affected application's version before delivery, including fixes and performance optimizations.
- Use `./bump-version.sh web` for dashboard changes and `./bump-version.sh function` for collector changes. Bump both when changes affect both applications.
- Keep the version sources and deployment values synchronized using the existing script; do not treat deployment-time package stamping as a version bump.

## Azure Storage History

- Never delete blobs, directories, containers, filesystems, storage accounts, or resource groups containing retained DVM history unless a human explicitly approves the exact destructive operation and names the target.
- A request to "start over", "reset", "rebuild", "clean up", or "redeploy" is not approval to delete Azure Storage data.
- Starting over means creating a new immutable run path and, after successful validation, updating only `current/manifest.json`.
- Application code must not call ADLS or Blob Storage delete APIs or configure automatic lifecycle deletion for retained DVM history.
- Paths under `raw/`, `curated/`, and `runs/` are append-only and use `overwrite=False`.
- Only `current/manifest.json` in the separate current-pointer container is replaceable. It is a pointer to an immutable completed run, not historical evidence.
- Local cleanup of `output/` never implies deletion of Azure Storage data.
- Preserve the storage account when replacing application infrastructure. Treat it as a separately protected data resource.
