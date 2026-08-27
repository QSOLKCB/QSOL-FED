from pathlib import Path

path = Path("tools/moriarty_isolation.py")
source = path.read_text(encoding="utf-8")
old = "TRUSTED_REGISTRY_BUILD_HOOK_ARCHIVES: frozenset[tuple[str, str, str]] = frozenset()\n"
new = '''TRUSTED_REGISTRY_BUILD_HOOK_ARCHIVES: frozenset[tuple[str, str, str]] = frozenset({
    ("curve25519-dalek", "4.1.3", "97fb8b7c4503de7d6ae7b42ab72a5a59857b4c937ec27a3d4539dba95b5ab2be"),
    ("generic-array", "0.14.7", "85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a"),
    ("httparse", "1.10.1", "6dbf3de79e51f3d586ab4cb9d5c3e2c14aa28ed23d180cf89b4df0454a69cc87"),
    ("libc", "0.2.189", "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2"),
    ("num-traits", "0.2.19", "071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841"),
    ("proc-macro2", "1.0.107", "985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9"),
    ("quote", "1.0.47", "1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001"),
    ("serde", "1.0.229", "4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba"),
    ("serde_core", "1.0.229", "67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48"),
    ("serde_json", "1.0.151", "c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14"),
    ("zmij", "1.0.23", "29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b"),
})
'''
old_count = source.count(old)
new_count = source.count(new)
if old_count == 1 and new_count == 0:
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
elif old_count == 0 and new_count == 1:
    print("Phase 9 hook allowlist already frozen")
else:
    raise SystemExit(f"hook allowlist source drift: old={old_count} new={new_count}")
