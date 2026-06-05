# Release v1.0.0

Sprint 8 is the final shippable release candidate for MicroPKI. After committing the repository, create and push the release tag with:

```bash
git add .
git commit -m "Release MicroPKI v1.0.0 Sprint 8"
git tag -a v1.0.0 -m "MicroPKI Sprint 8 final deliverable"
git push origin main --tags
```

Generated PKI data, logs, databases and demo work files are intentionally excluded through `.gitignore`.
