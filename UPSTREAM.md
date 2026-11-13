# Third-party source and binaries

This repository vendors unchanged source snapshots of:

- [LuLu v4.5.3](https://github.com/objective-see/LuLu/tree/v4.5.3), commit `d4679cb80081d1fb5160abc6bb87058794434235`, in `Vendor/LuLu/`.
- [Netiquette v2.3.0](https://github.com/objective-see/Netiquette/tree/v2.3.0), commit `cea0761b0f9121aa1544d6558ea71bd31a06ab11`, in `Vendor/Netiquette/`.

Both are from Objective-See and licensed under GPL-3.0. Their copyright notices and full license files remain in their directories. The Thunder Guard source in `Sources/` is also distributed under GPL-3.0; see `LICENSE.md`.

The release installer includes the unmodified, signed LuLu v4.5.3 app (which includes Netiquette v2.3.0). The LuLu binary was taken from the official `LuLu_4.5.3.dmg`, SHA-256 `E50625191B5F9FEDD56C545F2D630993470DBBA0BC12D85B737372C79CC91AFF`. The installer checks for an existing `/Applications/LuLu.app` and only copies the bundled one if none exists. Thunder Guard is independently built and does not modify LuLu or Thunder binaries.

LuLu's `App.entitlements` and `Extension.entitlements` request the Network Extension content-filter entitlement. This machine's available signing identities do not carry that entitlement. Rebuilding LuLu source and ad hoc signing its extension would not produce a working firewall. The signed original remains the active filter; the vendored source makes the dependency inspectable and rebuildable by a developer with the required entitlement.

`Integration/prepare.py` generates a separate modified LuLu source tree for a single-app development build. It embeds the Thunder Guard dashboard, uses its native rule editor in the same process, removes the optional Netiquette app, uses independent identifiers and storage, and parameterizes the publisher identity without removing XPC signature checks. It preserves upstream notices and includes the GPL-3.0 license. This generated fork is compile-only and is not installed or included in the existing release package. See [Integration/README.md](Integration/README.md) for outstanding signing and runtime validation.
