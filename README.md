# Rhen Vault

Rhen Vault is a desktop Obsidian plugin. It encrypts locked notes before they are written to disk, so a local AI tool that opens a locked note reads ciphertext instead of the note.

The plugin id is `rhen-info-vault`. Install it from Obsidian's community plugins once the listing is published. The release assets are `main.js`, `manifest.json`, and `styles.css`. The tag matches the version in `manifest.json`, with no `v` prefix.

This repository publishes those releases. The plugin source is private. Obsidian's community directory reviews that source through the Community Directory GitHub app.

Rhen Vault can read and write files outside the vault. That is how an image secret, a recovery file, and the optional Windows account protection work. The Windows setup runs only after you start it from Rhen Vault settings and approve the system prompt. It does not run on its own.

License: MIT.
