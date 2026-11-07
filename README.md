# Strongbox Login

A small, click-only browser integration for Strongbox. This is a security-focused fork of `strongbox-password-safe/browser-autofill`; the original README is preserved in `README.upstream.md` and the upstream license remains in `LICENSE.md`.

## Behavior

Open the toolbar popup on an HTTPS login page to see matching accounts. Choose an account to fill the visible top-level form. On an email-first step, it fills the username field. Open **Search other accounts** to find entries by title or abbreviation. If the saved site differs, confirm the displayed destination before filling. It does not invoke form submission. A site's own input handlers may react to a fill.

There is no automatic fill, page-load credential lookup, persistent content script, inline iframe UI, generic page-message bridge, clipboard access, record editing or password generation. Only the active tab is accessible after using the extension. Credentials expire after 45 seconds, are single-use, and cannot be used after navigation or a detected database lock.

The primary stored HTTPS URL matches the same origin or a child hostname on the same port. For example, `https://google.com` matches `https://accounts.google.com`. Saved subdomains do not match siblings or parents. A pinned Public Suffix List including private hosting boundaries blocks public suffixes such as `co.uk` and shared hosting suffixes such as `github.io` from authorizing child sites. Scheme-less and alternative KeePass URL fields are not supported yet. HTTP and subframe logins fail closed. At most 24 native results are considered, so this first version can omit a match beyond that page. Compatibility can be expanded with explicit policy and tests.

## Security limits

Read `hardened/SECURITY.md`. The native app and signed helper remain trusted components. This fork validates its own requests and responses; it cannot repair the native app's behavior for another client. Native-side issues identified in the audit are not claimed fixed here. No production vault is an automated-test fixture.

## Test and build

Use Node 24+ and Python 3. No npm dependency installation or dependency lifecycle scripts are needed. TweetNaCl 1.0.3 is vendored with its license and provenance, including matching npm integrity and upstream Git source.

```sh
node --test tests/*.test.mjs
python3 tools/build_hardened.py --out dist/production
python3 tools/build_hardened.py --fixture --out dist/synthetic
```

The builder refuses an existing output directory. Repeat builds to fresh directories and compare their contents. `SHA256SUMS.json` records every packaged file. The synthetic build has a separate identity and native host, and permits exact loopback HTTP only. It must never be registered with the real helper.

## Helium registration and installation

Use a reviewed, versioned release directory, not a development directory. Enable Developer mode in Helium's Extensions page and load the reviewed release as an unpacked extension. This gives the local files update authority; protect that directory and review each replacement.

```sh
python3 tools/register_native_host.py --extension /path/to/reviewed/release
```

Strongbox must be running with its Chrome/Firefox browser-extension service enabled. A refused native connection means that service is unavailable; installing a manifest alone does not start it.

Registration uses Helium's standard user-level `NativeMessagingHosts` directory, verifies the installed Strongbox helper's signature/team and root ownership, and allows only this fork's derived extension ID. It refuses to overwrite a different existing registration. Strongbox's own manifest installer does not currently enumerate Helium, so this local registration must be maintained when the app path or extension identity changes.

To roll back, disable Strongbox Login in Helium and remove only the registration written for this fork after verifying its contents. Do not re-enable an unreviewed release or modify any vault to roll back a browser integration.

## Source history

The public upstream 1.2.3 snapshot had malformed manifests/lockfile and did not reproduce store 1.2.5. `src/` preserves that historical source for comparison. The new shipped path is only `hardened/` plus the deterministic packaging tools; it does not build or load the historical `src/` tree.
