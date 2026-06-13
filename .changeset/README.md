# Changesets

This folder holds [changesets](https://github.com/changesets/changesets) for
the published package (`@eric-minassian/auth`). To record a change, run:

```sh
pnpm changeset
```

CI's release workflow opens a "Version Packages" PR; merging it publishes to
npm via Trusted Publishing (OIDC).
