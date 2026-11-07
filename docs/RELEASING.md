# Releasing

`scripts/ntm-install.sh` installs from GitHub Releases. There is no CI: a release
is built on the development machine and uploaded by hand.

## What a release holds

| File | |
| --- | --- |
| `ntm-<tag>.tar.gz` | `backend/` without its tests, `scripts/install-wazuh.sh`, `uninstall-wazuh.sh`, `wazuh-lib.sh`, and `wheels/` (the scanner's Python packages, for `--offline`) |
| `vulnmapper-<osd>.zip` | the plugin, one per dashboard version; it installs only into that exact version |
| `SHA256SUMS` | checksums of the above |

The bundle's name must hold the release's tag exactly: `ntm-install.sh` asks
GitHub for the tag and then looks for `ntm-<tag>.tar.gz`.

## Cutting one

You need what `scripts/send-plugin.sh` needs (nvm with node 18.19.0, the plugin
in `~/dev/OpenSearch-Dashboards/plugins/vulnmapper`), internet for the wheels, and
the GitHub CLI or a browser. Run the checks first:

```
scripts/test-wazuh-install.sh
scripts/test-ntm-install.sh
```

From a clean checkout of the commit to release (the script refuses a tree with
changes, because the bundle is taken from the commit):

```
scripts/build-release.sh --tag v1.0.0            # builds for 2.19.6
scripts/build-release.sh --tag v1.0.0 2.19.6 2.19.3   # or for several versions
```

`dist/` then holds the files. Upload all of them under the same tag:

```
git tag v1.0.0 && git push origin v1.0.0
gh release create v1.0.0 dist/* --title v1.0.0 --notes "..."
```

Or on github.com: Releases, Draft a new release, pick the tag, attach everything
in `dist/`, publish. `releases/latest` ignores drafts and pre-releases, so only a
published full release reaches users who do not pass `--version`.

Check it on the lab server: `sudo bash ntm-install.sh -i --dry-run` finds the
release, picks the zip, checks the downloads and changes nothing.

## A new dashboard version

When Wazuh moves to a new OpenSearch Dashboards version, build a zip for it and
release again; the version is in `/usr/share/wazuh-dashboard/package.json` on the
server. Update the supported versions in the README.

`scripts/ntm-install.sh` itself is not in the release: users fetch it from `main`,
so a change to it reaches them on merge and must keep working with the releases
already out.
