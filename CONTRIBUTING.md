# Contributing

This repository is published from SnoutData's main repository, which is private. Each commit here
is one change made there, copied across.

So a pull request here is not merged with the merge button. When we accept it, we apply your change
in the main repository with you as co-author, and the next sync brings it back here as a commit that
credits you. Your pull request is then closed with a link to that commit.

Before you open one: `bash scripts/test.sh` passes (it runs in a container; Docker or Podman is the
only thing you need installed). A change in behaviour that an existing client could see says so in the pull request,
with its reason.

Security problems go to a private report, never an issue: see [SECURITY.md](./SECURITY.md).

By contributing you agree that your change is licensed under the [Apache License 2.0](./LICENSE).
