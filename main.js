/* Rhen Vault — vault notes are encrypted at rest. This bundle must not log note text or passphrases. */
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => RhenVaultPlugin
});
module.exports = __toCommonJS(main_exports);
var import_child_process = require("child_process");
var import_fs6 = __toESM(require("fs"), 1);
var path2 = __toESM(require("path"), 1);
var import_obsidian5 = require("obsidian");

// src/sealing/attachments.ts
var ATTACHMENT_TYPES = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  svg: "image/svg+xml",
  bmp: "image/bmp",
  pdf: "application/pdf",
  mp3: "audio/mpeg",
  wav: "audio/wav",
  ogg: "audio/ogg",
  m4a: "audio/mp4",
  mp4: "video/mp4",
  webm: "video/webm",
  mov: "video/quicktime"
};
var ATTACHMENT_EXTENSIONS = new Set(Object.keys(ATTACHMENT_TYPES));
function extensionOf(vaultPath) {
  const name = vaultPath.replace(/\\/g, "/").split("/").pop() ?? "";
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return null;
  return name.slice(dot + 1).toLowerCase();
}
function isAttachmentPath(vaultPath) {
  const ext = extensionOf(vaultPath);
  return ext !== null && ATTACHMENT_EXTENSIONS.has(ext);
}
function attachmentMimeType(vaultPath) {
  const ext = extensionOf(vaultPath);
  return ext && ATTACHMENT_TYPES[ext] || "application/octet-stream";
}

// src/sealing/crypto.ts
var import_crypto = require("crypto");
var ENVELOPE_PREFIX = "SLATE1:";
var VERIFIER_PLAINTEXT = "slate-verifier-v1";
var DEFAULT_KDF = { N: 32768, r: 8, p: 1 };
var IV_LEN = 12;
var TAG_LEN = 16;
var KEY_LEN = 32;
function deriveKey(passphrase, salt, params = DEFAULT_KDF) {
  return (0, import_crypto.scryptSync)(passphrase, salt, KEY_LEN, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 128 * 1024 * 1024
  });
}
function wipeKey(key) {
  key?.fill(0);
}
function encryptWithKey(plain, key) {
  return sealBuffer(Buffer.from(plain, "utf8"), key);
}
function encryptBytes(plain, key) {
  return sealBuffer(Buffer.from(plain), key);
}
function decryptWithKey(payload, key) {
  const opened = openEnvelope(payload, key);
  return opened ? opened.toString("utf8") : null;
}
function decryptBytes(payload, key) {
  return openEnvelope(payload, key);
}
function sealBuffer(plain, key) {
  if (key.length !== KEY_LEN) {
    throw new Error("Rhen Vault key must be 32 bytes");
  }
  const iv = (0, import_crypto.randomBytes)(IV_LEN);
  const cipher = (0, import_crypto.createCipheriv)("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ENVELOPE_PREFIX + Buffer.concat([iv, tag, ciphertext]).toString("base64");
}
function openEnvelope(payload, key) {
  if (!payload.startsWith(ENVELOPE_PREFIX) || key.length !== KEY_LEN) return null;
  const raw = Buffer.from(payload.slice(ENVELOPE_PREFIX.length), "base64");
  if (raw.length < IV_LEN + TAG_LEN) return null;
  const iv = raw.subarray(0, IV_LEN);
  const tag = raw.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ciphertext = raw.subarray(IV_LEN + TAG_LEN);
  try {
    const decipher = (0, import_crypto.createDecipheriv)("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}
function isEnvelope(data) {
  return data.startsWith(ENVELOPE_PREFIX);
}
function isEnvelopeBytes(data) {
  if (data.length < ENVELOPE_PREFIX.length) return false;
  return Buffer.from(data.buffer, data.byteOffset, ENVELOPE_PREFIX.length).toString("latin1") === ENVELOPE_PREFIX;
}
function createVerifier(key) {
  return encryptWithKey(VERIFIER_PLAINTEXT, key);
}
function verifierMatches(envelope, key) {
  return decryptWithKey(envelope, key) === VERIFIER_PLAINTEXT;
}

// src/sealing/locks.ts
function normalizeVaultPath(vaultPath) {
  return vaultPath.replace(/\\/g, "/").replace(/^\/+/, "").replace(/\/+$/, "");
}
function fold(path3) {
  return normalizeVaultPath(path3).toLowerCase();
}
function pathIsInside(vaultPath, folder) {
  const path3 = fold(vaultPath);
  const prefix = fold(folder);
  if (!prefix) return false;
  return path3 === prefix || path3.startsWith(`${prefix}/`);
}
function listed(paths) {
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const raw of paths) {
    const norm = normalizeVaultPath(raw);
    if (!norm) continue;
    const key = norm.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(norm);
  }
  return out;
}
function containsFold(paths, vaultPath) {
  const wanted = fold(vaultPath);
  return listed(paths).some((item) => fold(item) === wanted);
}
function isLockedPath(vaultPath, rules) {
  const path3 = normalizeVaultPath(vaultPath);
  if (containsFold(rules.lockedFiles, path3)) return true;
  if (containsFold(rules.unlockedFiles, path3)) return false;
  if (listed(rules.unlockedFolders).some((folder) => pathIsInside(path3, folder))) return false;
  return listed(rules.lockedFolders).some((folder) => pathIsInside(path3, folder));
}
function folderIsLocked(folderPath, rules) {
  const folder = normalizeVaultPath(folderPath);
  if (!folder) return false;
  if (listed(rules.unlockedFolders).some((item) => pathIsInside(folder, item))) return false;
  return listed(rules.lockedFolders).some((item) => pathIsInside(folder, item));
}
function lockFile(rules, vaultPath) {
  const path3 = normalizeVaultPath(vaultPath);
  return {
    lockedFiles: listed([...rules.lockedFiles, path3]),
    lockedFolders: listed(rules.lockedFolders),
    unlockedFiles: listed(rules.unlockedFiles).filter((item) => fold(item) !== fold(path3)),
    unlockedFolders: listed(rules.unlockedFolders)
  };
}
function unlockLeavesFolderLocked(rules, vaultPath) {
  const path3 = normalizeVaultPath(vaultPath);
  if (!path3) return false;
  return listed(rules.lockedFolders).some((folder) => fold(folder) !== fold(path3) && pathIsInside(path3, folder));
}
function unlockFile(rules, vaultPath) {
  const path3 = normalizeVaultPath(vaultPath);
  const next = {
    lockedFiles: listed(rules.lockedFiles).filter((item) => fold(item) !== fold(path3)),
    lockedFolders: listed(rules.lockedFolders),
    unlockedFiles: listed(rules.unlockedFiles).filter((item) => fold(item) !== fold(path3)),
    unlockedFolders: listed(rules.unlockedFolders)
  };
  if (listed(next.lockedFolders).some((folder) => pathIsInside(path3, folder))) {
    next.unlockedFiles = listed([...next.unlockedFiles, path3]);
  }
  return next;
}
function lockFolder(rules, folderPath) {
  const folder = normalizeVaultPath(folderPath);
  return {
    lockedFiles: listed(rules.lockedFiles).filter((item) => !pathIsInside(item, folder)),
    lockedFolders: listed([...rules.lockedFolders.filter((item) => !pathIsInside(item, folder) || fold(item) === fold(folder)), folder]),
    unlockedFiles: listed(rules.unlockedFiles).filter((item) => !pathIsInside(item, folder)),
    unlockedFolders: listed(rules.unlockedFolders).filter((item) => !pathIsInside(item, folder))
  };
}
function parentOf(vaultPath) {
  const path3 = fold(vaultPath);
  const slash = path3.lastIndexOf("/");
  return slash === -1 ? "" : path3.slice(0, slash);
}
function renameLockPath(rules, oldPath, newPath, isFolder) {
  const from = normalizeVaultPath(oldPath);
  const to = normalizeVaultPath(newPath);
  const move = (items) => listed(items.map((item) => pathIsInside(item, from) ? `${to}${normalizeVaultPath(item).slice(from.length)}` : item));
  const sameParent = parentOf(from) === parentOf(to);
  const lockedFolders = move(rules.lockedFolders);
  const movedLocks = lockedFolders.filter((folder) => pathIsInside(folder, to));
  const keepException = (item) => sameParent || !pathIsInside(item, to) || movedLocks.some((folder) => pathIsInside(item, folder));
  let next = {
    lockedFiles: move(rules.lockedFiles),
    lockedFolders,
    unlockedFiles: move(rules.unlockedFiles).filter(keepException),
    unlockedFolders: move(rules.unlockedFolders).filter(keepException)
  };
  const wasLocked = isFolder ? folderIsLocked(from, rules) : isLockedPath(from, rules);
  const nowLocked = isFolder ? folderIsLocked(to, next) : isLockedPath(to, next);
  if (wasLocked && !nowLocked) next = isFolder ? lockFolder(next, to) : lockFile(next, to);
  return next;
}
function unlockFolder(rules, folderPath) {
  const folder = normalizeVaultPath(folderPath);
  const next = {
    lockedFiles: listed(rules.lockedFiles).filter((item) => !pathIsInside(item, folder)),
    lockedFolders: listed(rules.lockedFolders).filter((item) => !pathIsInside(item, folder)),
    unlockedFiles: listed(rules.unlockedFiles).filter((item) => !pathIsInside(item, folder)),
    unlockedFolders: listed(rules.unlockedFolders).filter((item) => !pathIsInside(item, folder))
  };
  if (next.lockedFolders.some((item) => pathIsInside(folder, item))) {
    next.unlockedFolders = listed([...next.unlockedFolders, folder]);
  }
  return next;
}

// src/sealing/integrity.ts
var RECORD_VERSION = "slate-locks-v1";
function canonical(rules) {
  const sorted = (items) => [...new Set(items.map(normalizeVaultPath).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  return {
    lockedFiles: sorted(rules.lockedFiles),
    lockedFolders: sorted(rules.lockedFolders),
    unlockedFiles: sorted(rules.unlockedFiles),
    unlockedFolders: sorted(rules.unlockedFolders)
  };
}
function sealLockRecord(record, key) {
  return encryptWithKey(
    JSON.stringify({
      v: RECORD_VERSION,
      rules: canonical(record.rules),
      extensions: [...record.extensions],
      extraBlockedPluginIds: [...record.extraBlockedPluginIds]
    }),
    key
  );
}
function openLockRecord(record, key) {
  if (!record) return null;
  const plain = decryptWithKey(record, key);
  if (plain === null) return null;
  try {
    const parsed = JSON.parse(plain);
    if (parsed.v !== RECORD_VERSION || !parsed.rules) return null;
    const list = (value) => Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
    return {
      rules: canonical({
        lockedFiles: list(parsed.rules.lockedFiles),
        lockedFolders: list(parsed.rules.lockedFolders),
        unlockedFiles: list(parsed.rules.unlockedFiles),
        unlockedFolders: list(parsed.rules.unlockedFolders)
      }),
      extensions: list(parsed.extensions),
      extraBlockedPluginIds: list(parsed.extraBlockedPluginIds)
    };
  } catch {
    return null;
  }
}
function sameKey(a, b) {
  return normalizeVaultPath(a).toLowerCase() === normalizeVaultPath(b).toLowerCase();
}
function union(a, b) {
  const out = [...a];
  for (const item of b) if (!out.some((existing) => sameKey(existing, item))) out.push(item);
  return out;
}
function intersect(a, b) {
  return a.filter((item) => b.some((other) => sameKey(item, other)));
}
function reconcileLocks(current, trusted) {
  const rules = {
    lockedFiles: union(current.lockedFiles, trusted.lockedFiles),
    lockedFolders: union(current.lockedFolders, trusted.lockedFolders),
    unlockedFiles: intersect(current.unlockedFiles, trusted.unlockedFiles),
    unlockedFolders: intersect(current.unlockedFolders, trusted.unlockedFolders)
  };
  const tampered = rules.lockedFiles.length !== current.lockedFiles.length || rules.lockedFolders.length !== current.lockedFolders.length || rules.unlockedFiles.length !== current.unlockedFiles.length || rules.unlockedFolders.length !== current.unlockedFolders.length;
  return { rules, tampered };
}
function reconcileRecord(current, trusted) {
  const locks = reconcileLocks(current.rules, trusted.rules);
  const extensions = union(current.extensions, trusted.extensions);
  const extraBlockedPluginIds = union(current.extraBlockedPluginIds, trusted.extraBlockedPluginIds);
  return {
    record: { rules: locks.rules, extensions, extraBlockedPluginIds },
    tampered: locks.tampered || extensions.length !== current.extensions.length || extraBlockedPluginIds.length !== current.extraBlockedPluginIds.length
  };
}
function adoptSealedPath(rules, vaultPath) {
  return isLockedPath(vaultPath, rules) ? null : lockFile(rules, vaultPath);
}

// src/sealing/access.ts
function detectAgent(stack, blockedIds) {
  const normalized = stack.replace(/\\/g, "/").toLowerCase();
  for (const id of blockedIds) {
    const needle = id.trim().toLowerCase();
    if (!needle) continue;
    if (normalized.includes(`/plugins/${needle}/`) || normalized.includes(`/plugins/${needle}.js`)) {
      return id;
    }
    if (needle.length >= 8 && normalized.includes(needle)) return id;
  }
  return null;
}

// src/harness/shields.ts
var SHIELD_MARKER = "rhen-vault-shield";
var HARNESS_START = "rhen-vault-locks:start";
var HARNESS_END = "rhen-vault-locks:end";
var LEGACY_SHIELD_MARKER = "slate-infosec-shield";
var LEGACY_HARNESS_START = "slate-infosec-locks:start";
var LEGACY_HARNESS_END = "slate-infosec-locks:end";
var PROSE = `<!-- ${SHIELD_MARKER} -->

# Sealed vault

Rhen Vault encrypts note text before it is written to disk. A file that starts with \`SLATE1:\` is ciphertext.

Do not decrypt those files. Do not ask for the passphrase. Do not copy note text out of Obsidian.

This file is not a security boundary. A local process can still read the ciphertext bytes. Images, PDFs, audio, and video inside a lock are sealed too. A plugin that reads those files without going through Obsidian still gets ciphertext.
`;
var IGNORE_HEADER = `# ${SHIELD_MARKER}
# Not a security boundary. Note text is encrypted at rest (SLATE1:).
# Rhen Vault merges per-folder lock patterns between the ${HARNESS_START} markers below.
# Edits outside the markers are preserved.
`;
var PROSE_FILES = [
  { path: "AGENTS.md", contents: PROSE },
  { path: "CLAUDE.md", contents: PROSE },
  { path: "GEMINI.md", contents: PROSE }
];
var IGNORE_FILES = [
  ".cursorignore",
  ".cursorindexingignore",
  ".geminiignore",
  ".aiderignore",
  ".aiexclude",
  ".ignore"
];
var SHIELD_FILES = [
  ...PROSE_FILES,
  ...IGNORE_FILES.map((path3) => ({ path: path3, contents: IGNORE_HEADER }))
];
var ROOT_CLEARTEXT = /* @__PURE__ */ new Set([
  ...PROSE_FILES.map((file) => file.path),
  ...IGNORE_FILES
]);

// src/sealing/seal.ts
var SealLockedError = class extends Error {
  path;
  constructor(path3) {
    super("Rhen Vault is locked");
    this.name = "SealLockedError";
    this.path = path3;
  }
};
var SealCorruptError = class extends Error {
  path;
  constructor(path3) {
    super("Rhen Vault cannot open this envelope");
    this.name = "SealCorruptError";
    this.path = path3;
  }
};
function normalize(vaultPath) {
  return vaultPath.replace(/\\/g, "/").replace(/^\/+/, "");
}
function isSealableExtension(vaultPath, state) {
  const path3 = normalize(vaultPath);
  const config = normalize(state.configDir);
  if (path3 === config || path3.startsWith(`${config}/`) || path3.split("/").includes(config)) {
    return false;
  }
  const name = path3.slice(path3.lastIndexOf("/") + 1);
  if (!path3.includes("/") && ROOT_CLEARTEXT.has(name)) return false;
  if (isAttachmentPath(path3)) return true;
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return false;
  const ext = name.slice(dot + 1).toLowerCase();
  return state.extensions.some((item) => item.toLowerCase() === ext);
}
function shouldSeal(vaultPath, state) {
  return isSealableExtension(vaultPath, state) && isLockedPath(vaultPath, state);
}
function incoming(data, vaultPath, state, agentId = null) {
  if (!shouldSeal(vaultPath, state) || !isEnvelope(data)) return data;
  if (!state.key || agentId) return data;
  return decryptWithKey(data, state.key) ?? data;
}
function outgoing(data, vaultPath, state, previous, agentId = null) {
  if (!shouldSeal(vaultPath, state)) return data;
  if (agentId) {
    if (previous !== null && data === previous) return data;
    throw new SealLockedError(vaultPath);
  }
  if (!state.key) {
    if (previous !== null && data === previous) return data;
    throw new SealLockedError(vaultPath);
  }
  if (isEnvelope(data)) {
    if (state.key && decryptWithKey(data, state.key) === null) throw new SealCorruptError(vaultPath);
    return data;
  }
  return encryptWithKey(data, state.key);
}
function resealPlaintext(vaultPath, data, state) {
  if (!shouldSeal(vaultPath, state) || isEnvelope(data) || !state.key) return null;
  return encryptWithKey(data, state.key);
}
function resealBytes(vaultPath, data, state) {
  if (!shouldSeal(vaultPath, state) || isEnvelopeBytes(data) || !state.key) return null;
  return Buffer.from(encryptBytes(data, state.key), "utf8");
}
function openBytes(data, key) {
  if (!isEnvelopeBytes(data)) return null;
  return decryptBytes(Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf8"), key);
}

// src/sealing/adapter.ts
function installSealAdapter(adapter, state, hooks) {
  const original = {
    read: adapter.read.bind(adapter),
    write: adapter.write.bind(adapter),
    append: adapter.append?.bind(adapter),
    process: adapter.process?.bind(adapter),
    readBinary: adapter.readBinary?.bind(adapter),
    writeBinary: adapter.writeBinary?.bind(adapter)
  };
  const caller = () => {
    if (hooks?.detectCaller) return hooks.detectCaller();
    return detectAgent(new Error().stack ?? "", state.blockedPluginIds);
  };
  const run = async (fn) => {
    hooks?.begin?.();
    try {
      return await fn();
    } finally {
      hooks?.end?.();
    }
  };
  adapter.read = (path3) => run(async () => {
    const agentId = shouldSeal(path3, state) ? caller() : null;
    const raw = await original.read(path3);
    if (agentId) hooks?.onAgentAccess?.(path3, agentId, "read");
    return incoming(raw, path3, state, agentId);
  });
  adapter.write = (path3, data, options) => run(async () => {
    const agentId = shouldSeal(path3, state) ? caller() : null;
    let previous = null;
    if (shouldSeal(path3, state) && (agentId || !state.key)) {
      try {
        previous = await original.read(path3);
      } catch {
        previous = null;
      }
    }
    if (agentId) hooks?.onAgentAccess?.(path3, agentId, "modify");
    let next;
    try {
      next = outgoingOrThrow(data, path3, state, previous, agentId, hooks);
    } catch (error) {
      if (error instanceof SealCorruptError) hooks?.onCorrupt?.(path3);
      throw error;
    }
    if (shouldSeal(path3, state) && !state.key && !agentId && !isEnvelope(next)) hooks?.onUserPlaintext?.(path3);
    await original.write(path3, next, options);
  });
  if (original.append) {
    adapter.append = async (path3, data, options) => {
      let current = "";
      try {
        current = await adapter.read(path3);
      } catch {
        current = "";
      }
      await adapter.write(path3, current + data, options);
    };
  }
  if (original.readBinary) {
    adapter.readBinary = (path3) => run(async () => {
      const raw = await original.readBinary(path3);
      const bytes = new Uint8Array(raw);
      if (!shouldSeal(path3, state) || !isEnvelopeBytes(bytes)) return raw;
      const agentId = caller();
      if (agentId) hooks?.onAgentAccess?.(path3, agentId, "read");
      if (agentId || !state.key) return raw;
      const plain = openBytes(bytes, state.key);
      if (!plain) return raw;
      return plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength);
    });
  }
  if (original.writeBinary) {
    adapter.writeBinary = (path3, data) => run(async () => {
      if (!shouldSeal(path3, state)) {
        await original.writeBinary(path3, data);
        return;
      }
      const agentId = caller();
      if (agentId) hooks?.onAgentAccess?.(path3, agentId, "modify");
      if (agentId || !state.key) throw new SealLockedError(path3);
      const bytes = new Uint8Array(data);
      if (isEnvelopeBytes(bytes)) {
        if (state.key && !openBytes(bytes, state.key)) {
          hooks?.onCorrupt?.(path3);
          throw new SealCorruptError(path3);
        }
        await original.writeBinary(path3, data);
        return;
      }
      const sealed = Buffer.from(encryptBytes(bytes, state.key), "utf8");
      await original.writeBinary(path3, sealed.buffer.slice(sealed.byteOffset, sealed.byteOffset + sealed.byteLength));
    });
  }
  if (original.process) {
    adapter.process = (path3, fn, options) => run(async () => {
      let agentHit = false;
      try {
        return await original.process(
          path3,
          (data) => {
            if (!shouldSeal(path3, state)) return fn(data);
            const agentId = caller();
            if (agentId) {
              agentHit = true;
              hooks?.onAgentAccess?.(path3, agentId, "modify");
              throw new SealLockedError(path3);
            }
            if (!state.key) throw new SealLockedError(path3);
            const plain = incoming(data, path3, state, null);
            const next = fn(plain);
            if (next === plain && isEnvelope(data)) return data;
            return outgoing(next, path3, state, data, null);
          },
          options
        );
      } catch (error) {
        if (error instanceof SealLockedError && !agentHit) hooks?.onLocked?.(error.path);
        else if (error instanceof SealCorruptError) hooks?.onCorrupt?.(error.path);
        throw error;
      }
    });
  }
  return {
    restore: () => {
      adapter.read = original.read;
      adapter.write = original.write;
      if (original.append) adapter.append = original.append;
      if (original.process) adapter.process = original.process;
      if (original.readBinary) adapter.readBinary = original.readBinary;
      if (original.writeBinary) adapter.writeBinary = original.writeBinary;
    },
    read: original.read,
    write: original.write
  };
}
function outgoingOrThrow(data, path3, state, previous, agentId, hooks) {
  try {
    return outgoing(data, path3, state, previous, agentId);
  } catch (error) {
    if (error instanceof SealLockedError && !agentId) hooks?.onLocked?.(error.path);
    throw error;
  }
}

// src/sealing/settings.ts
var ALWAYS_BLOCKED = [
  { id: "realclaudian", label: "Claudian" },
  { id: "copilot", label: "Copilot" },
  { id: "chatgpt-md", label: "ChatGPT MD" },
  { id: "ai-agent", label: "AI Agent" },
  { id: "agent", label: "Agent" }
];
var DEFAULT_SETTINGS = {
  salt: null,
  verifier: null,
  secretKind: "passphrase",
  kdfN: DEFAULT_KDF.N,
  kdfR: DEFAULT_KDF.r,
  kdfP: DEFAULT_KDF.p,
  extensions: ["md", "txt", "canvas"],
  extraBlockedPluginIds: [],
  lockedFiles: [],
  lockedFolders: [],
  unlockedFiles: [],
  unlockedFolders: [],
  syncedClaudeDenies: [],
  syncedOpencodePatterns: [],
  syncedPiDenies: [],
  syncedObsidianFilters: [],
  shieldsWritten: false,
  lockRecord: null,
  recoveryNoticeAck: false
};
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function mergeSettings(loaded) {
  const source = isRecord(loaded) ? loaded : null;
  const merged = { ...DEFAULT_SETTINGS, ...source ?? {} };
  merged.extensions = (merged.extensions ?? []).map((ext) => ext.trim().replace(/^\./, "").toLowerCase()).filter(Boolean);
  if (merged.extensions.length === 0) {
    merged.extensions = [...DEFAULT_SETTINGS.extensions];
  }
  merged.extraBlockedPluginIds = (merged.extraBlockedPluginIds ?? []).map((id) => id.trim()).filter(Boolean);
  merged.lockedFiles = cleanPaths(merged.lockedFiles);
  merged.lockedFolders = cleanPaths(merged.lockedFolders);
  merged.unlockedFiles = cleanPaths(merged.unlockedFiles);
  merged.unlockedFolders = cleanPaths(merged.unlockedFolders);
  merged.syncedClaudeDenies = cleanEntries(merged.syncedClaudeDenies);
  merged.syncedOpencodePatterns = cleanEntries(merged.syncedOpencodePatterns);
  merged.syncedPiDenies = cleanEntries(merged.syncedPiDenies);
  merged.syncedObsidianFilters = cleanEntries(merged.syncedObsidianFilters);
  merged.secretKind = merged.secretKind === "image" ? "image" : "passphrase";
  delete merged.helloCredentialId;
  if (!merged.kdfN) merged.kdfN = DEFAULT_KDF.N;
  if (!merged.kdfR) merged.kdfR = DEFAULT_KDF.r;
  if (!merged.kdfP) merged.kdfP = DEFAULT_KDF.p;
  return merged;
}
function blockedPluginIds(settings) {
  return [
    .../* @__PURE__ */ new Set([
      ...ALWAYS_BLOCKED.map((plugin) => plugin.id),
      ...settings.extraBlockedPluginIds
    ])
  ];
}
function labelForPlugin(id) {
  return ALWAYS_BLOCKED.find((plugin) => plugin.id === id)?.label ?? id;
}
function cleanPaths(paths) {
  return [...new Set((paths ?? []).map(normalizeVaultPath).filter(Boolean))];
}
function cleanEntries(entries) {
  return [...new Set((entries ?? []).map((entry) => entry.trim()).filter(Boolean))];
}

// src/harness/harness.ts
var CLAUDE_SETTINGS_PATH = ".claude/settings.json";
var OPENCODE_CONFIG_PATH = "opencode.json";
var GROK_CONFIG_PATH = ".grok/config.toml";
var PI_PERMISSIONS_PATH = ".pi/permissions.json";
function unique(paths) {
  return [...new Set(paths.map(normalizeVaultPath).filter(Boolean))];
}
function buildIgnorePatterns(rules) {
  const out = [];
  for (const file of unique(rules.lockedFiles)) out.push(`/${file}`);
  for (const folder of unique(rules.lockedFolders)) out.push(`/${folder}/**`);
  for (const file of unique(rules.unlockedFiles)) out.push(`!/${file}`);
  for (const folder of unique(rules.unlockedFolders)) out.push(`!/${folder}/**`);
  return out;
}
function buildClaudeDenies(rules) {
  const out = [];
  for (const target of lockedTargets(rules, "/**")) out.push(`Read(./${target})`, `Edit(./${target})`);
  return [...new Set(out)];
}
function buildOpencodePatterns(rules) {
  const out = [];
  for (const target of lockedTargets(rules, "/**")) out.push(target, `**/${target}`);
  return [...new Set(out)];
}
function buildGrokDenies(rules) {
  const out = [];
  for (const target of lockedTargets(rules, "/**")) out.push(`Read(${target})`, `Edit(${target})`);
  return [...new Set(out)];
}
function buildPiDenies(rules) {
  const out = [];
  for (const target of lockedTargets(rules, "/*")) {
    for (const tool of ["Read", "Edit", "Write"]) out.push(`${tool}(${target})`, `${tool}(*/${target})`);
  }
  return [...new Set(out)];
}
function lockedTargets(rules, folderSuffix) {
  return [...unique(rules.lockedFiles), ...unique(rules.lockedFolders).map((folder) => `${folder}${folderSuffix}`)];
}
function buildObsidianFilters(rules) {
  const out = [];
  for (const file of unique(rules.lockedFiles)) out.push(file);
  for (const folder of unique(rules.lockedFolders)) out.push(`${folder}/`);
  return [...new Set(out)];
}
function stripBlock(lines) {
  const kept = [];
  let inBlock = false;
  for (const line of lines) {
    if (line.includes(HARNESS_START) || line.includes(LEGACY_HARNESS_START)) {
      inBlock = true;
      continue;
    }
    if (line.includes(HARNESS_END) || line.includes(LEGACY_HARNESS_END)) {
      inBlock = false;
      continue;
    }
    if (!inBlock) kept.push(line);
  }
  return kept;
}
function blockFor(patterns) {
  return [
    `# ${HARNESS_START} (managed by Rhen Vault - do not edit between markers)`,
    ...patterns,
    `# ${HARNESS_END}`
  ].join("\n");
}
function mergeIgnoreFile(current, patterns) {
  const kept = stripBlock((current ?? "").split(/\r?\n/));
  while (kept.length > 0 && kept[kept.length - 1].trim() === "") kept.pop();
  if (patterns.length === 0) return kept.length === 0 ? "" : `${kept.join("\n")}
`;
  if (kept.length === 0) return `${blockFor(patterns)}
`;
  return `${kept.join("\n")}

${blockFor(patterns)}
`;
}
function ensureIgnoreContents(current, patterns) {
  const base = current ?? "";
  const withHeader = base.includes(SHIELD_MARKER) || base.includes(LEGACY_SHIELD_MARKER) ? base : `${IGNORE_HEADER}${base ? `
${base.replace(/^\n+/, "")}` : ""}`;
  return mergeIgnoreFile(withHeader, patterns);
}
function parseJsonObject(text) {
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}
function stringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}
function sameSet(a, b) {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((item) => set.has(item));
}
function mergeClaudeSettings(current, previouslySynced, wanted) {
  const root = { ...current ?? {} };
  const permissionsRaw = root.permissions;
  const permissions = permissionsRaw && typeof permissionsRaw === "object" && !Array.isArray(permissionsRaw) ? { ...permissionsRaw } : {};
  const prev = new Set(previouslySynced);
  const want = new Set(wanted);
  const deny = stringArray(permissions.deny).filter((entry) => !prev.has(entry) || want.has(entry));
  for (const entry of want) {
    if (!deny.includes(entry)) deny.push(entry);
  }
  const before = stringArray(
    permissionsRaw && typeof permissionsRaw === "object" && !Array.isArray(permissionsRaw) ? permissionsRaw.deny : []
  );
  permissions.deny = deny;
  root.permissions = permissions;
  return { next: root, changed: !sameSet(before, deny) || current === null };
}
function mergeObsidianFilters(current, previouslySynced, wanted) {
  const root = { ...current ?? {} };
  const prev = new Set(previouslySynced);
  const want = new Set(wanted);
  const filters = stringArray(root.userIgnoreFilters).filter((entry) => !prev.has(entry) || want.has(entry));
  for (const entry of want) {
    if (!filters.includes(entry)) filters.push(entry);
  }
  const before = stringArray(current?.userIgnoreFilters);
  root.userIgnoreFilters = filters;
  return { next: root, changed: !sameSet(before, filters) || current === null };
}
var mergePiPermissions = mergeClaudeSettings;
function isRecord2(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function mergeOpencodeConfig(current, previouslySynced, wanted) {
  const root = { ...current ?? {} };
  if (current === null) root.$schema = "https://opencode.ai/config.json";
  const raw = root.permission;
  const permission = typeof raw === "string" ? { "*": raw } : isRecord2(raw) ? { ...raw } : {};
  const prev = new Set(previouslySynced);
  const want = new Set(wanted);
  let touched = false;
  for (const tool of ["read", "edit"]) {
    const rule = permission[tool];
    if (typeof rule === "string" && wanted.length === 0) continue;
    const entries = typeof rule === "string" ? [["*", rule]] : isRecord2(rule) ? Object.entries(rule) : [];
    const kept = entries.filter(([pattern]) => !prev.has(pattern) && !want.has(pattern));
    if (kept.length === entries.length && wanted.length === 0) continue;
    const merged = {};
    for (const [pattern, value] of kept) merged[pattern] = value;
    for (const pattern of wanted) merged[pattern] = "deny";
    if (Object.keys(merged).length === 0) delete permission[tool];
    else permission[tool] = merged;
    touched = true;
  }
  if (touched) {
    if (Object.keys(permission).length === 0) delete root.permission;
    else root.permission = permission;
  }
  return { next: root, changed: JSON.stringify(root) !== JSON.stringify(current) };
}
function mergeGrokConfig(current, denies) {
  const outside = stripBlock((current ?? "").split(/\r?\n/));
  if (outside.some((line) => /^\s*(\[\[?\s*permission\s*[\].]|permission\s*[.=])/.test(line))) return null;
  const lines = denies.length === 0 ? [] : ["[permission]", "deny = [", ...denies.map((deny) => `  ${JSON.stringify(deny)},`), "]"];
  return mergeIgnoreFile(current, lines);
}
function codexSnippet(rules) {
  const denies = [...unique(rules.lockedFiles), ...unique(rules.lockedFolders).map((folder) => `${folder}/**`)];
  const lines = denies.map((pattern) => `  "${pattern}" = "deny"`);
  return [
    "# Rhen Vault-managed Codex denies. Paste under your profile's [permissions.<name>.filesystem] table.",
    "# Project config cannot be trusted for this; keep it in ~/.codex/config.toml.",
    ...lines
  ].join("\n");
}

// src/harness/sync.ts
var GuardSync = class {
  constructor(host) {
    this.host = host;
  }
  async sync() {
    const installed = this.host.requireInstalled();
    const rules = this.host.rules();
    const patterns = buildIgnorePatterns(rules);
    const touched = [];
    const attempt = async (vaultPath, run) => {
      try {
        if (await run()) touched.push(vaultPath);
      } catch (error) {
        console.error(`Rhen Vault: could not update ${vaultPath}`, error);
      }
    };
    for (const name of IGNORE_FILES) {
      await attempt(name, async () => {
        const current = await this.readRaw(installed, name);
        if (current === null && patterns.length === 0) return false;
        const next = current === null ? ensureIgnoreContents(null, patterns) : mergeIgnoreFile(current, patterns);
        if (current === next) return false;
        await installed.write(name, next);
        return true;
      });
    }
    const jsonGuards = [
      {
        path: CLAUDE_SETTINGS_PATH,
        wanted: buildClaudeDenies(rules),
        key: "syncedClaudeDenies",
        merge: mergeClaudeSettings
      },
      {
        path: OPENCODE_CONFIG_PATH,
        wanted: buildOpencodePatterns(rules),
        key: "syncedOpencodePatterns",
        merge: mergeOpencodeConfig
      },
      {
        path: PI_PERMISSIONS_PATH,
        wanted: buildPiDenies(rules),
        key: "syncedPiDenies",
        merge: mergePiPermissions
      }
    ];
    for (const guard of jsonGuards) {
      await attempt(guard.path, async () => {
        const result = await this.syncJsonGuard(
          installed,
          guard.path,
          guard.wanted,
          (current) => guard.merge(current, this.host.settings[guard.key], guard.wanted)
        );
        if (result !== "skipped") this.host.settings[guard.key] = [...guard.wanted];
        return result === "written";
      });
    }
    await attempt(GROK_CONFIG_PATH, async () => {
      const grokDenies = buildGrokDenies(rules);
      const grokCurrent = await this.readRaw(installed, GROK_CONFIG_PATH);
      if (grokCurrent === null && grokDenies.length === 0) return false;
      const next = mergeGrokConfig(grokCurrent, grokDenies);
      if (next === null) {
        console.warn(`Rhen Vault: left ${GROK_CONFIG_PATH} unchanged (it already defines [permission]).`);
        return false;
      }
      if (next === grokCurrent) return false;
      await this.writeGuard(installed, GROK_CONFIG_PATH, next);
      return true;
    });
    const appPath = `${this.host.app.vault.configDir}/app.json`;
    await attempt(appPath, () => this.syncObsidianFiltersFile(installed, appPath, rules));
    return { files: touched };
  }
  async readRaw(installed, vaultPath) {
    try {
      return await installed.read(vaultPath);
    } catch {
      return null;
    }
  }
  async syncJsonGuard(installed, vaultPath, wanted, merge) {
    const current = await this.readRaw(installed, vaultPath);
    if (current === null && wanted.length === 0) return "unchanged";
    const parsed = current === null ? null : parseJsonObject(current);
    if (current !== null && parsed === null) {
      console.warn(`Rhen Vault: left ${vaultPath} unchanged (could not parse JSON).`);
      return "skipped";
    }
    const { next, changed } = merge(parsed);
    if (!changed && current !== null) return "unchanged";
    await this.writeGuard(installed, vaultPath, `${JSON.stringify(next, null, 2)}
`);
    return "written";
  }
  async writeGuard(installed, vaultPath, contents) {
    const slash = vaultPath.lastIndexOf("/");
    if (slash > 0) {
      const dir = vaultPath.slice(0, slash);
      const adapter = this.host.app.vault.adapter;
      if (!await adapter.exists(dir)) await adapter.mkdir(dir);
    }
    await installed.write(vaultPath, contents);
  }
  async syncObsidianFiltersFile(installed, appPath, rules) {
    const wanted = buildObsidianFilters(rules);
    const current = await this.readRaw(installed, appPath);
    if (current === null) return false;
    const parsed = parseJsonObject(current);
    if (parsed === null) {
      console.warn("Rhen Vault: left app.json unchanged (could not parse JSON).");
      return false;
    }
    const { next, changed } = mergeObsidianFilters(parsed, this.host.settings.syncedObsidianFilters, wanted);
    if (!changed) {
      this.host.settings.syncedObsidianFilters = [...wanted];
      return false;
    }
    await installed.write(appPath, `${JSON.stringify(next, null, 2)}
`);
    this.host.settings.syncedObsidianFilters = [...wanted];
    return true;
  }
};

// src/visuals/toast.ts
var import_obsidian = require("obsidian");
var COPY = {
  read: { kicker: "Blocked", title: "Read blocked", detail: (agent) => `${agent} tried to read a locked note.` },
  modify: { kicker: "Blocked", title: "Change blocked", detail: (agent) => `${agent} tried to change a locked note.` },
  resealed: {
    kicker: "Sealed",
    title: "Outside change sealed",
    detail: (agent) => `${agent} wrote plaintext into a locked note. Rhen Vault encrypted it again.`
  },
  pending: {
    kicker: "Exposed",
    title: "Unlock to re-seal",
    detail: (agent) => `${agent} wrote plaintext into a locked note. Unlock Rhen Vault to encrypt it.`
  },
  waiting: {
    kicker: "Locked",
    title: "Not encrypted yet",
    detail: () => "You created this note in a locked folder. Rhen Vault encrypts it when you unlock."
  }
};
var AccessToasts = class {
  constructor(doc) {
    this.doc = doc;
  }
  host = null;
  seen = /* @__PURE__ */ new Map();
  show(detail) {
    const key = `${detail.action}:${detail.path}`;
    const now = Date.now();
    if (now - (this.seen.get(key) ?? 0) < 8e3) return;
    this.seen.set(key, now);
    const host = this.ensureHost();
    const toast = host.createDiv({ cls: "slate-toast" });
    toast.setAttr("role", "status");
    const badge = toast.createDiv({ cls: "rhen-toast-badge" });
    (0, import_obsidian.setIcon)(badge, "shield");
    const copy = toast.createDiv({ cls: "rhen-toast-copy" });
    const text = COPY[detail.action];
    copy.createDiv({ cls: "rhen-toast-kicker", text: text.kicker });
    copy.createDiv({ cls: "rhen-toast-title", text: text.title });
    copy.createDiv({ cls: "rhen-toast-detail", text: text.detail(detail.agentLabel) });
    copy.createDiv({ cls: "rhen-toast-file", text: detail.fileName });
    const close = toast.createEl("button", { cls: "rhen-toast-close", text: "\xD7" });
    close.setAttr("aria-label", "Dismiss");
    const remove = () => toast.remove();
    close.addEventListener("click", remove);
    window.setTimeout(remove, 7e3);
    while (host.childElementCount > 4) host.firstElementChild?.remove();
  }
  destroy() {
    this.host?.remove();
    this.host = null;
    this.seen.clear();
  }
  ensureHost() {
    if (this.host?.isConnected) return this.host;
    this.host = this.doc.body.createDiv({ cls: "rhen-toast-host" });
    this.host.setAttr("aria-live", "polite");
    return this.host;
  }
};

// src/visuals/ui.ts
var import_obsidian2 = require("obsidian");

// src/secrets/image-secret.ts
var IMAGE_SAMPLES = 128;
function imageSampleSecret(pixels, width, height, salt) {
  if (width < 1 || height < 1) throw new Error("Rhen Vault could not read that image.");
  if (salt.length < 8) throw new Error("Image salt is too short.");
  if (pixels.length < width * height * 4) throw new Error("Image data is incomplete.");
  let state = 2166136261;
  for (const byte of salt) state = nextSample(state ^ byte);
  const parts = [];
  for (let sample = 0; sample < IMAGE_SAMPLES; sample++) {
    state = nextSample(state);
    const x = state % width;
    state = nextSample(state);
    const y = state % height;
    const offset = (y * width + x) * 4;
    parts.push(byteHex(pixels[offset]), byteHex(pixels[offset + 1]), byteHex(pixels[offset + 2]));
  }
  return parts.join("");
}
function nextSample(seed) {
  let value = seed + 1831565813 >>> 0;
  value = Math.imul(value ^ value >>> 15, value | 1);
  value ^= value + Math.imul(value ^ value >>> 7, value | 61);
  return (value ^ value >>> 14) >>> 0;
}
function byteHex(value) {
  return (value & 255).toString(16).padStart(2, "0");
}

// src/visuals/ui.ts
var SetupModal = class extends import_obsidian2.Modal {
  constructor(app, vaultPath, onSubmit) {
    super(app);
    this.vaultPath = vaultPath;
    this.onSubmit = onSubmit;
  }
  passphrase = "";
  confirm = "";
  shields = true;
  onOpen() {
    const { contentEl } = this;
    this.modalEl.addClass("rhen-modal");
    contentEl.createEl("h2", { text: "Set how Rhen Vault unlocks" });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "The secret stays in memory for this session. Nothing is locked until you right-click a note or folder and choose Lock from AI. A locked folder includes its subfolders. Export a recovery file from Rhen Vault settings before uninstalling: uninstalling deletes the salt, and the same passphrase alone will not reopen sealed notes."
    });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Ignore files for Cursor, Claude, Codex, and similar tools are optional. They do not keep notes private. Encryption does."
    });
    new import_obsidian2.Setting(contentEl).setName("Write agent ignore files").setDesc("Optional. These files only ask tools to skip locked notes. A tool that opens them anyway gets encrypted text, not the note.").addToggle((toggle) => toggle.setValue(true).onChange((value) => {
      this.shields = value;
    }));
    contentEl.createEl("h3", { text: "Password" });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Use at least 16 characters. A long password slows guessing. It does not protect Obsidian while it is unlocked."
    });
    new import_obsidian2.Setting(contentEl).setName("Password").addText((text) => {
      text.inputEl.type = "password";
      text.inputEl.autocomplete = "new-password";
      text.onChange((value) => {
        this.passphrase = value;
      });
    });
    new import_obsidian2.Setting(contentEl).setName("Confirm password").addText((text) => {
      text.inputEl.type = "password";
      text.inputEl.autocomplete = "new-password";
      text.onChange((value) => {
        this.confirm = value;
      });
    });
    new import_obsidian2.Setting(contentEl).addButton(
      (button) => button.setButtonText("Save password").setCta().onClick(() => this.submitPassword())
    );
    contentEl.createEl("h3", { text: "Image" });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Rhen Vault samples 128 colors from the picture and uses them as the secret. The picture is not saved. Keep that file outside this vault and outside any folder an AI tool can open, and do not edit it. You will choose the same file again to unlock."
    });
    const imageInput = contentEl.createEl("input", { cls: "rhen-file-input", type: "file" });
    imageInput.accept = "image/*";
    imageInput.addEventListener("change", () => {
      const file = imageInput.files?.[0];
      imageInput.value = "";
      if (file) void this.submitImage(file);
    });
    new import_obsidian2.Setting(contentEl).addButton(
      (button) => button.setButtonText("Choose image").onClick(() => imageInput.click())
    );
  }
  submitPassword() {
    if (this.passphrase.length < 16) {
      new import_obsidian2.Notice("Use at least 16 characters. A long password slows guessing. It does not protect Obsidian while it is unlocked.");
      return;
    }
    if (this.passphrase !== this.confirm) {
      new import_obsidian2.Notice("Passwords do not match.");
      return;
    }
    const secret = this.passphrase;
    const shields = this.shields;
    this.passphrase = "";
    this.confirm = "";
    this.close();
    this.onSubmit({ kind: "passphrase", secret, shields });
  }
  async submitImage(file) {
    const location = fileLocation(file);
    if (location && imageInsideVault(location, this.vaultPath)) {
      new import_obsidian2.Notice("Choose an image outside this vault. An AI that can open the vault could read the picture and rebuild the key.");
      return;
    }
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const secret = await secretFromImage(file, salt);
      const shields = this.shields;
      this.close();
      this.onSubmit({ kind: "image", secret, shields, salt });
    } catch (error) {
      new import_obsidian2.Notice(error instanceof Error ? error.message : "Rhen Vault could not read that image.");
    }
  }
  onClose() {
    this.passphrase = "";
    this.confirm = "";
    this.contentEl.empty();
  }
};
var UnlockModal = class extends import_obsidian2.Modal {
  constructor(app, kind, vaultPath, salt, onSubmit) {
    super(app);
    this.kind = kind;
    this.vaultPath = vaultPath;
    this.salt = salt;
    this.onSubmit = onSubmit;
  }
  passphrase = "";
  onOpen() {
    const { contentEl } = this;
    this.modalEl.addClass("rhen-modal");
    contentEl.createEl("h2", { text: "Unlock Rhen Vault" });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Notes stay encrypted on disk after unlock. Obsidian decrypts them in memory so you can edit."
    });
    if (this.kind === "image") this.imageUnlock(contentEl);
    else this.passwordUnlock(contentEl);
  }
  passwordUnlock(contentEl) {
    new import_obsidian2.Setting(contentEl).setName("Password").addText((text) => {
      text.inputEl.type = "password";
      text.inputEl.autocomplete = "current-password";
      text.inputEl.addEventListener("keydown", (event) => {
        if (event.key === "Enter") this.submitPassword();
      });
      text.onChange((value) => {
        this.passphrase = value;
      });
    });
    new import_obsidian2.Setting(contentEl).addButton(
      (button) => button.setButtonText("Unlock").setCta().onClick(() => this.submitPassword())
    );
  }
  imageUnlock(contentEl) {
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Choose the same image file you used when Rhen Vault was set up. It still has to sit outside this vault."
    });
    const imageInput = contentEl.createEl("input", { cls: "rhen-file-input", type: "file" });
    imageInput.accept = "image/*";
    imageInput.addEventListener("change", () => {
      const file = imageInput.files?.[0];
      imageInput.value = "";
      if (file) void this.submitImage(file);
    });
    new import_obsidian2.Setting(contentEl).addButton(
      (button) => button.setButtonText("Choose image").setCta().onClick(() => imageInput.click())
    );
  }
  submitPassword() {
    const secret = this.passphrase;
    this.passphrase = "";
    this.close();
    this.onSubmit(secret);
  }
  async submitImage(file) {
    if (!this.salt) {
      new import_obsidian2.Notice("This vault has no image secret.");
      return;
    }
    const location = fileLocation(file);
    if (location && imageInsideVault(location, this.vaultPath)) {
      new import_obsidian2.Notice("Choose the original image from outside this vault.");
      return;
    }
    try {
      const secret = await secretFromImage(file, this.salt);
      this.close();
      this.onSubmit(secret);
    } catch (error) {
      new import_obsidian2.Notice(error instanceof Error ? error.message : "Rhen Vault could not read that image.");
    }
  }
  onClose() {
    this.passphrase = "";
    this.contentEl.empty();
  }
};
function fileLocation(file) {
  const direct = file.path;
  if (direct) return direct;
  try {
    const electron = window.require?.("electron");
    return electron?.webUtils?.getPathForFile?.(file) ?? "";
  } catch {
    return "";
  }
}
function imageInsideVault(filePath, vaultPath) {
  if (!vaultPath || !filePath) return false;
  const file = filePath.replace(/\//g, "\\").toLowerCase();
  const vault = vaultPath.replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
  return file === vault || file.startsWith(`${vault}\\`);
}
async function secretFromImage(file, salt) {
  const bitmap = await createImageBitmap(file);
  try {
    const scale = Math.min(1, 512 / Math.max(bitmap.width, bitmap.height));
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = createFragment().createEl("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("Rhen Vault could not read that image.");
    context.drawImage(bitmap, 0, 0, width, height);
    const pixels = context.getImageData(0, 0, width, height).data;
    return imageSampleSecret(pixels, width, height, salt);
  } finally {
    bitmap.close();
  }
}
var ConfirmModal = class extends import_obsidian2.Modal {
  constructor(app, copy, onConfirm) {
    super(app);
    this.copy = copy;
    this.onConfirm = onConfirm;
  }
  onOpen() {
    const { contentEl } = this;
    this.modalEl.addClass("rhen-modal");
    contentEl.createEl("h2", { text: this.copy.title });
    contentEl.createEl("p", { cls: "rhen-note", text: this.copy.body });
    new import_obsidian2.Setting(contentEl).addButton((button) => button.setButtonText("Cancel").onClick(() => this.close())).addButton(
      (button) => button.setButtonText(this.copy.confirm).setWarning().onClick(() => {
        this.close();
        this.onConfirm();
      })
    );
  }
  onClose() {
    this.contentEl.empty();
  }
};
function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.body.createEl("a", { attr: { href: url, download: filename } });
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 5e3);
}
var UninstallNoticeModal = class extends import_obsidian2.Modal {
  constructor(app, controller, onAck) {
    super(app);
    this.controller = controller;
    this.onAck = onAck;
  }
  onOpen() {
    const { contentEl } = this;
    this.modalEl.addClass("rhen-modal");
    contentEl.createEl("h2", { text: "Keep your notes recoverable" });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Locked notes are stored as ciphertext, and only this vault's secret opens them. Disabling Rhen Vault is safe: settings stay, and everything reopens when you re-enable it."
    });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Uninstalling deletes Rhen Vault's settings, including the salt. After that, the same passphrase or image alone will not reopen sealed notes."
    });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Before uninstalling, either unseal your notes (plaintext goes back on disk), or export a recovery file and keep it somewhere safe. After reinstalling, import the recovery file and unlock with the original secret."
    });
    new import_obsidian2.Setting(contentEl).addButton(
      (button) => button.setButtonText("Export recovery file").onClick(() => {
        const json = this.controller.exportRecovery();
        if (!json) {
          new import_obsidian2.Notice("Rhen Vault has no secret to back up yet.");
          return;
        }
        downloadTextFile("rhen-vault-recovery.json", json);
        new import_obsidian2.Notice("Recovery file exported. Keep it somewhere safe.");
      })
    ).addButton(
      (button) => button.setButtonText("I understand").setCta().onClick(() => {
        this.close();
        this.onAck();
      })
    );
  }
  onClose() {
    this.contentEl.empty();
  }
};
var ExposureModal = class extends import_obsidian2.Modal {
  constructor(app, info, actions) {
    super(app);
    this.info = info;
    this.actions = actions;
  }
  onOpen() {
    const { contentEl } = this;
    this.modalEl.addClass("rhen-modal");
    contentEl.createEl("h2", { text: "Rhen Vault will not unlock here yet" });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: `These accounts can change the plugin files: ${this.info.writers.join(", ")}. A changed plugin could capture the passphrase, so Rhen Vault keeps the session locked. Locked notes are untouched and still encrypted.`
    });
    contentEl.createEl("p", {
      cls: "rhen-note",
      text: "Usual cause: a leftover sandbox or test account (for example CodexSandboxUsers) still has write access to the vault. Pick a fix, then choose Check again."
    });
    if (this.info.fixCommands) {
      new import_obsidian2.Setting(contentEl).setName("Remove their write access").setDesc("Run these in an elevated PowerShell or Command Prompt (right-click, Run as administrator). If the permission is inherited from a parent folder, run the same remove against that parent instead.").addButton(
        (button) => button.setButtonText("Copy fix").onClick(() => {
          void navigator.clipboard.writeText(this.info.fixCommands ?? "").then(
            () => new import_obsidian2.Notice("Copied. Paste into an elevated prompt, then Check again."),
            () => new import_obsidian2.Notice("Rhen Vault could not copy to the clipboard.")
          );
        })
      );
    }
    new import_obsidian2.Setting(contentEl).addButton((button) => button.setButtonText("Close").onClick(() => this.close())).addButton(
      (button) => button.setButtonText("Check again").setCta().onClick(() => {
        this.close();
        this.actions.onRecheck();
      })
    );
    if (this.info.canProtect) {
      new import_obsidian2.Setting(contentEl).setName("Strongest option").setDesc("Move the vault behind a separate Windows account instead, so your normal account and everything running in it lose access entirely.").addButton(
        (button) => button.setButtonText("Set up separate account").onClick(() => {
          this.close();
          this.actions.onProtect();
        })
      );
    }
  }
  onClose() {
    this.contentEl.empty();
  }
};
var RhenVaultSettingTab = class extends import_obsidian2.PluginSettingTab {
  controller;
  constructor(app, plugin) {
    super(app, plugin);
    this.controller = plugin;
  }
  display() {
    const { containerEl } = this;
    containerEl.empty();
    new import_obsidian2.Setting(containerEl).setName(`Rhen Vault ${this.controller.manifest.version}`).setHeading();
    const blocked = this.controller.agentBlockLabels();
    const locks = this.controller.settings.lockedFolders.length + this.controller.settings.lockedFiles.length;
    const status = !this.controller.settings.verifier ? "Set a passphrase, then right-click a note or folder and choose Lock from AI." : this.controller.isUnlocked() ? `Session open. ${locks} lock ${locks === 1 ? "rule" : "rules"}. Locked notes stay encrypted on disk.` : "Session locked. Unlock to edit locked notes. They stay encrypted on disk.";
    containerEl.createEl("p", { cls: "rhen-settings-lead", text: status });
    containerEl.createEl("p", {
      cls: "rhen-note",
      text: blocked.length ? `${blocked.join(", ")} is enabled. A read of a locked note from that plugin raises a block alert.` : "Right-click a note to lock it, or a folder to lock that folder and its subfolders."
    });
    containerEl.createEl("p", {
      cls: "rhen-note",
      text: "Rhen Vault seals markdown, text, and canvas files inside a lock, and also images, PDFs, audio, and video stored in that lock. Obsidian shows those embeds while Rhen Vault is unlocked. A plugin that reads the file on its own still gets ciphertext. File recovery can keep plaintext snapshots. Turn that core plugin off."
    });
    if (!this.controller.settings.verifier) {
      new import_obsidian2.Setting(containerEl).setName("Create a passphrase").addButton(
        (button) => button.setButtonText("Set passphrase").setCta().onClick(() => this.controller.openSetup())
      );
    } else if (this.controller.isUnlocked()) {
      new import_obsidian2.Setting(containerEl).setName("Lock").addButton(
        (button) => button.setButtonText("Lock").onClick(() => this.controller.lock())
      );
    } else {
      new import_obsidian2.Setting(containerEl).setName("Unlock").addButton(
        (button) => button.setButtonText("Unlock").setCta().onClick(() => this.controller.openUnlock())
      );
    }
    new import_obsidian2.Setting(containerEl).setName("Sealed extensions").setDesc("Comma-separated. Defaults to md, txt, canvas.").addText(
      (text) => text.setValue(this.controller.settings.extensions.join(", ")).onChange(async (value) => {
        const extensions = value.split(",").map((item) => item.trim().replace(/^\./, "").toLowerCase()).filter(Boolean);
        this.controller.settings.extensions = extensions.length ? extensions : ["md", "txt", "canvas"];
        this.controller.state.extensions = this.controller.settings.extensions;
        await this.controller.saveSettings();
      })
    );
    new import_obsidian2.Setting(containerEl).setName("Additional blocked plugins").setDesc("Claudian, Copilot, ChatGPT MD, AI Agent, and Agent are always blocked. Add other plugin ids, separated by commas.").addText(
      (text) => text.setPlaceholder("plugin-id").setValue(this.controller.settings.extraBlockedPluginIds.join(", ")).onChange(async (value) => {
        this.controller.settings.extraBlockedPluginIds = value.split(",").map((item) => item.trim()).filter(Boolean);
        await this.controller.saveSettings();
      })
    );
    new import_obsidian2.Setting(containerEl).setName("Seal locked notes").setDesc("Encrypt plaintext notes that are already covered by a lock. Already sealed notes are left as they are.").addButton(
      (button) => button.setButtonText("Seal locked notes").onClick(async () => {
        try {
          const count = await this.controller.sealAll();
          new import_obsidian2.Notice(count === 0 ? "No plaintext notes to seal." : `Sealed ${count} notes.`);
        } catch {
          new import_obsidian2.Notice("Unlock Rhen Vault before sealing notes.");
        }
      })
    );
    new import_obsidian2.Setting(containerEl).setName("Write ignore files").setDesc("Writes AGENTS.md, CLAUDE.md, GEMINI.md, and merges the lock list into harness ignore files, deny rules for Claude Code, OpenCode, Grok Build, and Pi, and Obsidian excluded files. Existing files without the Rhen Vault marker are left alone, except ignore files which gain a marked block.").addButton(
      (button) => button.setButtonText("Write shield files").onClick(async () => {
        const result = await this.controller.writeShields();
        const skipped = result.skipped.length ? ` Left ${result.skipped.join(", ")} unchanged.` : "";
        new import_obsidian2.Notice(`Wrote ${result.written.length} shield files.${skipped}`);
      })
    );
    new import_obsidian2.Setting(containerEl).setName("Codex deny rules").setDesc("Codex only reads deny rules from your user config, which Rhen Vault does not edit. Copy these and paste them into ~/.codex/config.toml under your profile's filesystem table.").addButton(
      (button) => button.setButtonText("Copy").onClick(async () => {
        try {
          await navigator.clipboard.writeText(this.controller.codexRules());
          new import_obsidian2.Notice("Copied Codex deny rules.");
        } catch {
          new import_obsidian2.Notice("Rhen Vault could not copy to the clipboard.");
        }
      })
    );
    if (this.controller.settings.verifier) {
      new import_obsidian2.Setting(containerEl).setName("Recovery file").setDesc("Holds the salt and verifier, never the secret. Export before uninstalling: uninstalling deletes the salt, and the same passphrase alone will not reopen sealed notes. Import after reinstalling, then unlock with the original secret.").addButton(
        (button) => button.setButtonText("Safe uninstall steps").onClick(() => this.controller.showRecoveryInfo())
      ).addButton(
        (button) => button.setButtonText("Export").onClick(() => {
          const json = this.controller.exportRecovery();
          if (!json) {
            new import_obsidian2.Notice("Rhen Vault has no secret to back up yet.");
            return;
          }
          downloadTextFile("rhen-vault-recovery.json", json);
          new import_obsidian2.Notice("Recovery file exported. Keep it somewhere safe.");
        })
      ).addButton(
        (button) => button.setButtonText("Import").onClick(() => {
          const input = containerEl.createEl("input", {
            cls: "rhen-file-input",
            type: "file",
            attr: { accept: ".json,application/json" }
          });
          input.onchange = () => {
            const file = input.files?.[0];
            if (!file) return;
            void file.text().then((text) => this.controller.importRecoveryFile(JSON.parse(text))).then((ok) => {
              new import_obsidian2.Notice(
                ok ? "Recovery file imported. Unlock with the original secret." : "That file is not a Rhen Vault recovery file."
              );
            }).catch(() => new import_obsidian2.Notice("Rhen Vault could not read that file."));
          };
          input.click();
        })
      );
    }
    if (this.controller.isAccountProtected()) {
      new import_obsidian2.Setting(containerEl).setName("Separate Windows account").setDesc("On. Only the protected account, SYSTEM, and elevated administrators can open this vault's files. AI tools running in your normal account cannot read or change them, even when Obsidian is closed.").addButton(
        (button) => button.setButtonText("Undo").setWarning().onClick(() => this.controller.confirmAccountUndo())
      );
    } else if (this.controller.canUseAccountProtection()) {
      new import_obsidian2.Setting(containerEl).setName("Separate Windows account").setDesc("Strongest option. Moves this vault into a folder that your normal Windows account, and every AI tool running in it, cannot open, even when Obsidian is closed. You open it from an Obsidian (Protected) shortcut on the same desktop. Needs admin approval once.").addButton(
        (button) => button.setButtonText("Set up").onClick(() => this.controller.confirmAccountProtection())
      );
    }
    new import_obsidian2.Setting(containerEl).setName("Plugin file protection").setDesc("Rhen Vault refuses to unlock while another account can rewrite the plugin files, because a changed plugin could capture the passphrase. Locked notes stay encrypted. Check here to see who is listed and how to fix it.").addButton(
      (button) => button.setButtonText("Check now").onClick(() => {
        void this.controller.checkPluginWriters().then((writers) => {
          if (writers.length > 0) this.controller.showExposureInfo(writers);
          else new import_obsidian2.Notice("Only you, SYSTEM, and administrators can change the plugin files.");
        });
      })
    );
    new import_obsidian2.Setting(containerEl).setName("Unseal notes").setDesc("Writes note text back to disk as plaintext. Local agents will be able to read them.").addButton(
      (button) => button.setButtonText("Unseal").setWarning().onClick(() => {
        new ConfirmModal(
          this.app,
          {
            title: "Unseal notes?",
            body: "This writes note text back to disk as plaintext. Claudian, Cursor, Claude, and Codex will be able to read those files.",
            confirm: "Unseal"
          },
          () => {
            void this.controller.unsealAll().then(
              (count) => new import_obsidian2.Notice(`Unsealed ${count} notes.`),
              () => new import_obsidian2.Notice("Unlock Rhen Vault before unsealing notes.")
            );
          }
        ).open();
      })
    );
  }
};

// src/vault/fs-guard.ts
var import_fs2 = __toESM(require("fs"), 1);

// src/utilities/vault-path.ts
var import_fs = __toESM(require("fs"), 1);
var path = __toESM(require("path"), 1);
function vaultRelative(base, candidate) {
  const resolved = path.isAbsolute(candidate) ? candidate : path.resolve(base, candidate);
  const relative2 = path.relative(base, resolved);
  if (!relative2 || relative2.startsWith("..") || path.isAbsolute(relative2)) return null;
  return relative2.split(path.sep).join("/");
}
function safeJoin(base, vaultPath) {
  const parts = vaultPath.split("/").filter(Boolean);
  if (parts.some((part) => part === "." || part === "..")) return null;
  const full = path.join(base, ...parts);
  const relative2 = path.relative(base, full);
  if (relative2.startsWith("..") || path.isAbsolute(relative2)) return null;
  return full;
}
async function readHead(full, length) {
  try {
    const handle = await import_fs.default.promises.open(full, "r");
    try {
      const buffer = Buffer.alloc(length);
      const { bytesRead } = await handle.read(buffer, 0, length, 0);
      return buffer.toString("utf8", 0, bytesRead);
    } finally {
      await handle.close();
    }
  } catch {
    return null;
  }
}

// src/vault/fs-guard.ts
var FilesystemGuard = class {
  constructor(host) {
    this.host = host;
  }
  install() {
    const mutable = import_fs2.default;
    const readFile = mutable.readFile;
    const readFileSync = mutable.readFileSync;
    const readPromise = mutable.promises.readFile;
    const writeFile = mutable.writeFile;
    const writeFileSync = mutable.writeFileSync;
    const writePromise = mutable.promises.writeFile;
    const probe = (target) => {
      if (typeof target === "string") this.noteExternalRead(target);
    };
    const guard = (target, data) => this.guardedWriteData(target, data);
    mutable.readFile = (target, ...args) => {
      probe(target);
      return readFile(target, ...args);
    };
    mutable.readFileSync = (target, ...args) => {
      probe(target);
      return readFileSync(target, ...args);
    };
    mutable.promises.readFile = (target, ...args) => {
      probe(target);
      return readPromise(target, ...args);
    };
    mutable.writeFile = (target, data, ...args) => writeFile(target, guard(target, data), ...args);
    mutable.writeFileSync = (target, data, ...args) => writeFileSync(target, guard(target, data), ...args);
    mutable.promises.writeFile = (target, data, ...args) => writePromise(target, guard(target, data), ...args);
    this.host.restoreFs = () => {
      mutable.readFile = readFile;
      mutable.readFileSync = readFileSync;
      mutable.promises.readFile = readPromise;
      mutable.writeFile = writeFile;
      mutable.writeFileSync = writeFileSync;
      mutable.promises.writeFile = writePromise;
    };
  }
  guardedWriteData(target, data) {
    if (this.host.adapterDepth > 0 || this.host.sealingDisk || typeof target !== "string") return data;
    const bytes = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : null;
    if (typeof data !== "string" && !bytes) return data;
    const base = this.host.basePath();
    if (!base) return data;
    const relative2 = vaultRelative(base, target);
    if (!relative2 || !shouldSeal(relative2, this.host.state)) return data;
    const sealed = bytes ? resealBytes(relative2, bytes, this.host.state) : resealPlaintext(relative2, data, this.host.state);
    if (sealed) return sealed;
    if (this.host.state.key || (bytes ? isEnvelopeBytes(bytes) : isEnvelope(data))) return data;
    const full = safeJoin(base, relative2);
    if (!full) return data;
    this.host.sealingDisk = true;
    try {
      const existing = import_fs2.default.readFileSync(full);
      if (existing.subarray(0, ENVELOPE_PREFIX.length).toString("utf8") !== ENVELOPE_PREFIX) return data;
      return existing;
    } catch {
      return data;
    } finally {
      this.host.sealingDisk = false;
    }
  }
  noteExternalRead(candidate) {
    if (this.host.adapterDepth > 0 || this.host.sealingDisk) return;
    const base = this.host.basePath();
    if (!base) return;
    const relative2 = vaultRelative(base, candidate);
    if (!relative2 || !shouldSeal(relative2, this.host.state)) return;
    const agentId = detectAgent(new Error().stack ?? "", this.host.state.blockedPluginIds);
    if (!agentId) return;
    this.host.reportAgentAccess(relative2, agentId, "read");
  }
};

// src/vault/lock-actions.ts
var import_obsidian3 = require("obsidian");
var import_fs3 = __toESM(require("fs"), 1);
var LockActions = class {
  constructor(host) {
    this.host = host;
  }
  register() {
    this.host.observe(
      this.host.app.vault.on("rename", (file, oldPath) => {
        this.followRename(file, oldPath);
      })
    );
    this.host.observe(
      this.host.app.workspace.on("file-menu", (menu, file) => {
        this.addLockItems(menu, [file]);
      })
    );
    this.host.observe(
      this.host.app.workspace.on("files-menu", (menu, files) => {
        this.addLockItems(menu, files);
      })
    );
  }
  addLockItems(menu, files) {
    if (files.length === 1 && files[0] instanceof import_obsidian3.TFile && !isSealableExtension(files[0].path, this.host.state)) {
      return;
    }
    const locked = files.map((file) => this.itemIsLocked(file));
    if (locked.some((value) => !value)) {
      menu.addItem((item) => {
        item.setTitle(files.length === 1 && files[0] instanceof import_obsidian3.TFolder ? "Lock folder from AI" : "Lock from AI").setIcon("shield").setSection("action").onClick(() => {
          void this.lockSelection(files);
        });
      });
    }
    if (locked.some(Boolean)) {
      menu.addItem((item) => {
        item.setTitle(files.length === 1 && files[0] instanceof import_obsidian3.TFolder ? "Unlock folder from AI" : "Unlock from AI").setIcon("shield-off").setSection("action").onClick(() => {
          void this.unlockSelection(files);
        });
      });
    }
  }
  itemIsLocked(file) {
    if (file instanceof import_obsidian3.TFolder) return folderIsLocked(file.path, this.host.rules());
    return isLockedPath(file.path, this.host.rules());
  }
  async lockSelection(files) {
    let rules = this.host.rules();
    for (const file of files) {
      rules = file instanceof import_obsidian3.TFolder ? lockFolder(rules, file.path) : lockFile(rules, file.path);
    }
    this.host.commitRules(rules);
    await this.host.saveSettings();
    const folder = files.length === 1 && files[0] instanceof import_obsidian3.TFolder;
    if (!this.host.state.key) {
      await this.host.syncHarnessGuards();
      await this.host.saveSettings();
      new import_obsidian3.Notice(
        folder ? "Folder locked. Right-click it again to unlock it. Notes are encrypted after you unlock Rhen Vault." : "Locked from AI. Right-click it again to unlock it. Notes are encrypted after you unlock Rhen Vault."
      );
      if (this.host.sessionBlocked()) this.host.confirmAccountProtection();
      return;
    }
    const sealed = (await this.rewrite(files, "seal")).opened;
    await this.host.syncHarnessGuards();
    await this.host.saveSettings();
    new import_obsidian3.Notice(
      sealed === 0 ? folder ? "Folder locked. Notes saved inside it are encrypted." : "Locked from AI." : `Locked ${sealed} ${sealed === 1 ? "note" : "notes"} from AI.`
    );
  }
  async unlockSelection(files) {
    if (!this.host.state.key) {
      if (await this.selectionHasEnvelope(files)) {
        new import_obsidian3.Notice("Unlock Rhen Vault before changing locks. These notes are already encrypted.");
        this.host.openUnlockOrSetup();
        return;
      }
      let rules = this.host.rules();
      for (const file of files) {
        rules = file instanceof import_obsidian3.TFolder ? unlockFolder(rules, file.path) : unlockFile(rules, file.path);
      }
      this.host.commitRules(rules);
      await this.host.saveSettings();
      await this.host.syncHarnessGuards();
      await this.host.saveSettings();
      const folder = files.length === 1 && files[0] instanceof import_obsidian3.TFolder;
      new import_obsidian3.Notice(folder ? "Folder unlocked." : "Unlocked from AI.");
      return;
    }
    const run = async () => {
      const key = this.host.state.key;
      if (!key) {
        new import_obsidian3.Notice("Unlock Rhen Vault before changing locks.");
        return;
      }
      const damaged = await this.damagedEnvelopes(files, key);
      if (damaged.length > 0) {
        if (damaged.length === 1) {
          new import_obsidian3.Notice(
            `Rhen Vault could not decrypt ${damaged[0]} with this secret. The lock stays on. Restore that note from backup.`
          );
        } else {
          new import_obsidian3.Notice(
            `Rhen Vault could not decrypt ${damaged.length} notes with this secret. Locks stay on. Restore those notes from backup.`
          );
        }
        return;
      }
      let rules = this.host.rules();
      for (const file of files) {
        rules = file instanceof import_obsidian3.TFolder ? unlockFolder(rules, file.path) : unlockFile(rules, file.path);
      }
      this.host.commitRules(rules);
      await this.host.saveSettings();
      const { opened, failed } = await this.rewrite(files, "open");
      await this.host.syncHarnessGuards();
      await this.host.saveSettings();
      if (failed.length > 0) {
        new import_obsidian3.Notice(
          `Rhen Vault unlocked the files but could not decrypt ${failed.length} of them with this secret. Restore ${failed.length === 1 ? "that note" : "those notes"} from backup.`
        );
        return;
      }
      new import_obsidian3.Notice(`Unlocked ${opened} ${opened === 1 ? "note" : "notes"}. Agents can read them again.`);
    };
    const includesFolder = files.some((file) => file instanceof import_obsidian3.TFolder);
    const exceptions = files.filter((file) => !(file instanceof import_obsidian3.TFolder) && unlockLeavesFolderLocked(this.host.rules(), file.path));
    if (!includesFolder && exceptions.length > 0) {
      const one = exceptions.length === 1;
      this.confirmUnlock(
        {
          title: one ? "Unlock this note?" : "Unlock these notes?",
          body: one ? `This writes ${exceptions[0].path} back to disk as plaintext. AI tools will be able to read that note and look inside its folder to reach it. The folder stays locked, and every other file in it stays encrypted.` : "This writes the selected notes back to disk as plaintext. AI tools will be able to read those notes and look inside their folders to reach them. Those folders stay locked, and every other file in them stays encrypted.",
          confirm: one ? "Unlock this note" : "Unlock these notes"
        },
        run
      );
      return;
    }
    if (files.length === 1 && !includesFolder) {
      await run();
      return;
    }
    this.confirmUnlock(
      {
        title: "Unlock from AI?",
        body: "This writes the selected notes back to disk as plaintext, including notes in subfolders. AI agents will be able to read them.",
        confirm: "Unlock"
      },
      run
    );
  }
  /**
   * Sealed files under the selection that the current key cannot open.
   * Unlock must keep the lock on these instead of stranding their envelopes
   * in files Rhen Vault will never decrypt. Only files still covered by a lock
   * are checked; plaintext and already-unlocked files open trivially.
   */
  async damagedEnvelopes(roots, key) {
    const installed = this.host.requireInstalled();
    const damaged = [];
    for (const file of roots.flatMap((root) => this.collectFiles(root))) {
      if (!isSealableExtension(file.path, this.host.state)) continue;
      if (!shouldSeal(file.path, this.host.state)) continue;
      if (isAttachmentPath(file.path)) {
        const full = this.host.diskPath(file.path);
        if (!full) continue;
        let bytes;
        try {
          bytes = await import_fs3.default.promises.readFile(full);
        } catch {
          continue;
        }
        if (isEnvelopeBytes(bytes) && openBytes(bytes, key) === null) damaged.push(file.path);
        continue;
      }
      let raw;
      try {
        raw = await installed.read(file.path);
      } catch {
        continue;
      }
      if (isEnvelope(raw) && decryptWithKey(raw, key) === null) damaged.push(file.path);
    }
    return damaged;
  }
  confirmUnlock(copy, run) {
    new ConfirmModal(this.host.app, copy, () => {
      void run();
    }).open();
  }
  async rewrite(roots, mode) {
    const installed = this.host.requireInstalled();
    const key = this.host.state.key;
    if (!key) throw new SealLockedError("");
    let count = 0;
    const failed = [];
    for (const file of roots.flatMap((root) => this.collectFiles(root))) {
      if (!isSealableExtension(file.path, this.host.state)) continue;
      const covered = shouldSeal(file.path, this.host.state);
      if (isAttachmentPath(file.path)) {
        if (mode === "seal" && covered && await this.host.sealAttachment(file.path, key)) count += 1;
        else if (mode === "open" && !covered) {
          if (await this.host.openAttachment(file.path, key)) count += 1;
          else {
            const full = this.host.diskPath(file.path);
            if (full) {
              try {
                const bytes = await import_fs3.default.promises.readFile(full);
                if (isEnvelopeBytes(bytes)) failed.push(file.path);
              } catch {
              }
            }
          }
        }
        continue;
      }
      const raw = await installed.read(file.path);
      if (mode === "seal" && covered && !isEnvelope(raw)) {
        await installed.write(file.path, encryptWithKey(raw, key));
        count += 1;
      } else if (mode === "open" && !covered && isEnvelope(raw)) {
        const plain = decryptWithKey(raw, key);
        if (plain === null) {
          failed.push(file.path);
          continue;
        }
        await installed.write(file.path, plain);
        count += 1;
      }
    }
    await this.host.refreshOpenNotes();
    return { opened: count, failed };
  }
  /**
   * Runs synchronously inside Obsidian's rename event so the new path is
   * covered before the open editor saves its buffer there.
   */
  followRename(file, oldPath) {
    const before = this.host.rules();
    const after = renameLockPath(before, oldPath, file.path, file instanceof import_obsidian3.TFolder);
    const changed = JSON.stringify(before) !== JSON.stringify(after);
    if (changed) this.host.commitRules(after);
    const covered = this.collectFiles(file).some((item) => shouldSeal(item.path, this.host.state));
    if (!changed && !covered) return;
    void this.afterRename(file, changed, covered);
  }
  async afterRename(file, changed, covered) {
    try {
      if (changed) await this.host.saveSettings();
      if (covered) {
        if (this.host.state.key) await this.rewrite([file], "seal");
        else new import_obsidian3.Notice(`Rhen Vault: ${file.name} moved into a lock. Unlock Rhen Vault to encrypt it.`);
      }
      if (changed) {
        await this.host.syncHarnessGuards();
        await this.host.saveSettings();
      }
    } catch (error) {
      console.error("Rhen Vault: could not update locks after a move", error);
    }
  }
  async selectionHasEnvelope(files) {
    const base = this.host.basePath();
    if (!base) return false;
    for (const file of files.flatMap((item) => this.collectFiles(item))) {
      if (!isSealableExtension(file.path, this.host.state)) continue;
      const full = safeJoin(base, file.path);
      if (!full) continue;
      if (await readHead(full, ENVELOPE_PREFIX.length) === ENVELOPE_PREFIX) return true;
    }
    return false;
  }
  collectFiles(file) {
    if (file instanceof import_obsidian3.TFile) return [file];
    if (file instanceof import_obsidian3.TFolder) return file.children.flatMap((child) => this.collectFiles(child));
    return [];
  }
};

// src/vault/media.ts
var import_fs4 = __toESM(require("fs"), 1);
var MediaStore = class {
  constructor(host) {
    this.host = host;
  }
  /**
   * Obsidian loads images and other embeds from a resource URL, not from the
   * vault read API. While the session is unlocked, serve a memory blob of the
   * decrypted bytes. The file on disk stays an envelope.
   */
  installResourcePaths() {
    const adapter = this.host.app.vault.adapter;
    const original = adapter.getResourcePath?.bind(adapter);
    if (!original) return;
    adapter.getResourcePath = (vaultPath) => {
      try {
        const key = this.host.state.key;
        if (!key || !shouldSeal(vaultPath, this.host.state)) return original(vaultPath);
        if (detectAgent(new Error().stack ?? "", this.host.state.blockedPluginIds)) return original(vaultPath);
        const full = this.diskPath(vaultPath);
        if (!full) return original(vaultPath);
        const mtime = import_fs4.default.statSync(full).mtimeMs;
        const cached = this.host.blobUrls.get(vaultPath);
        if (cached?.mtime === mtime) return cached.url;
        this.forgetBlob(vaultPath);
        const plain = openBytes(import_fs4.default.readFileSync(full), key);
        if (!plain) return original(vaultPath);
        const url = URL.createObjectURL(new Blob([plain], { type: attachmentMimeType(vaultPath) }));
        this.host.blobUrls.set(vaultPath, { url, mtime });
        return url;
      } catch {
        return original(vaultPath);
      }
    };
    this.host.restoreResourcePath = () => {
      adapter.getResourcePath = original;
      this.revokeBlobUrls();
    };
  }
  revokeBlobUrls() {
    for (const entry of this.host.blobUrls.values()) URL.revokeObjectURL(entry.url);
    this.host.blobUrls.clear();
  }
  forgetBlob(vaultPath) {
    const entry = this.host.blobUrls.get(vaultPath);
    if (!entry) return;
    URL.revokeObjectURL(entry.url);
    this.host.blobUrls.delete(vaultPath);
  }
  diskPath(vaultPath) {
    const base = this.host.basePath();
    return base ? safeJoin(base, vaultPath) : null;
  }
  /** Encrypt a locked attachment's bytes in place. False when it is already an envelope. */
  async sealAttachment(vaultPath, key) {
    const full = this.diskPath(vaultPath);
    if (!full) return false;
    const bytes = await import_fs4.default.promises.readFile(full);
    if (isEnvelopeBytes(bytes)) return false;
    await this.writeDisk(full, Buffer.from(encryptBytes(bytes, key), "utf8"));
    this.forgetBlob(vaultPath);
    return true;
  }
  /** Write an unlocked attachment's original bytes back. False when it is not an envelope this key opens. */
  async openAttachment(vaultPath, key) {
    const full = this.diskPath(vaultPath);
    if (!full) return false;
    const plain = openBytes(await import_fs4.default.promises.readFile(full), key);
    if (!plain) return false;
    await this.writeDisk(full, plain);
    this.forgetBlob(vaultPath);
    return true;
  }
  /** Rhen Vault's own disk write. The fs write guard skips it, so plaintext from an explicit unlock lands as written. */
  async writeDisk(full, data) {
    this.host.sealingDisk = true;
    try {
      if (typeof data === "string") await import_fs4.default.promises.writeFile(full, data, "utf8");
      else await import_fs4.default.promises.writeFile(full, data);
    } finally {
      this.host.sealingDisk = false;
    }
  }
};

// src/vault/watch.ts
var import_fs5 = __toESM(require("fs"), 1);
var import_obsidian4 = require("obsidian");
var OUTSIDE = "A program outside Obsidian";
var GUARD_PATHS = new Set(
  [...IGNORE_FILES, CLAUDE_SETTINGS_PATH, OPENCODE_CONFIG_PATH, GROK_CONFIG_PATH, PI_PERMISSIONS_PATH].map(
    (item) => item.toLowerCase()
  )
);
var VaultWatch = class {
  constructor(host) {
    this.host = host;
  }
  register() {
    this.host.app.workspace.onLayoutReady(() => {
      this.host.observe(this.host.app.vault.on("create", (file) => void this.inspectOnDisk(file)));
      this.host.observe(this.host.app.vault.on("modify", (file) => void this.inspectOnDisk(file)));
      void this.adoptSealedFiles().catch((error) => console.error("Rhen Vault: startup lock scan failed", error));
    });
    const vault = this.host.app.vault;
    this.host.observe(
      vault.on("raw", (changed) => {
        if (GUARD_PATHS.has(normalizeVaultPath(changed).toLowerCase())) this.scheduleGuardSync();
      })
    );
  }
  async inspectOnDisk(file) {
    if (!(file instanceof import_obsidian4.TFile) || !isSealableExtension(file.path, this.host.state)) return;
    const installed = this.host.installed;
    if (!installed) return;
    if (this.host.inspecting.has(file.path)) {
      this.host.reinspect.add(file.path);
      return;
    }
    this.host.inspecting.add(file.path);
    try {
      let envelope;
      let sealed = false;
      if (isAttachmentPath(file.path)) {
        const full = this.host.diskPath(file.path);
        if (!full) return;
        const bytes = await import_fs5.default.promises.readFile(full);
        envelope = isEnvelopeBytes(bytes);
        const next = resealBytes(file.path, bytes, this.host.state);
        if (next) {
          await this.host.writeDisk(full, next);
          this.host.forgetBlob(file.path);
          sealed = true;
        }
      } else {
        const raw = await installed.read(file.path);
        envelope = isEnvelope(raw);
        const next = resealPlaintext(file.path, raw, this.host.state);
        if (next) {
          await installed.write(file.path, next);
          sealed = true;
        }
      }
      if (sealed) {
        this.host.exposedNotice.delete(file.path);
        this.host.toasts.show({ path: file.path, fileName: file.name, agentLabel: OUTSIDE, action: "resealed" });
        await this.host.refreshOpenNotes();
        return;
      }
      if (envelope) {
        if (isAttachmentPath(file.path)) this.host.forgetBlob(file.path);
        const adopted = adoptSealedPath(this.host.rules(), file.path);
        if (adopted) {
          this.host.commitRules(adopted);
          await this.host.saveSettings();
          this.scheduleGuardSync();
        }
        return;
      }
      if (!shouldSeal(file.path, this.host.state) || this.host.exposedNotice.has(file.path)) return;
      this.host.exposedNotice.add(file.path);
      this.host.toasts.show({
        path: file.path,
        fileName: file.name,
        agentLabel: OUTSIDE,
        action: this.host.userPlaintext.delete(file.path) ? "waiting" : "pending"
      });
    } catch {
    } finally {
      this.host.inspecting.delete(file.path);
      if (this.host.reinspect.delete(file.path)) void this.inspectOnDisk(file);
    }
  }
  /** Startup pass: every sealed file is locked, and plaintext under a lock is reported. */
  async adoptSealedFiles() {
    const base = this.host.basePath();
    if (!base) return;
    let rules = this.host.rules();
    let adopted = 0;
    let exposed = 0;
    for (const file of this.host.app.vault.getFiles()) {
      if (!isSealableExtension(file.path, this.host.state)) continue;
      const full = safeJoin(base, file.path);
      const head = full ? await readHead(full, ENVELOPE_PREFIX.length) : null;
      if (head === null) continue;
      if (head === ENVELOPE_PREFIX) {
        const next = adoptSealedPath(rules, file.path);
        if (next) {
          rules = next;
          adopted += 1;
        }
      } else if (isLockedPath(file.path, rules)) {
        exposed += 1;
      }
    }
    if (adopted > 0) {
      this.host.commitRules(rules);
      await this.host.saveSettings();
      this.scheduleGuardSync();
    }
    if (exposed > 0 && !this.host.state.key) {
      new import_obsidian4.Notice(`Rhen Vault: ${exposed} locked ${exposed === 1 ? "note is" : "notes are"} not encrypted. Unlock Rhen Vault to seal them.`);
    }
  }
  scheduleGuardSync() {
    if (this.host.guardSyncTimer !== null) window.clearTimeout(this.host.guardSyncTimer);
    this.host.guardSyncTimer = window.setTimeout(() => {
      this.host.guardSyncTimer = null;
      void this.host.syncHarnessGuards().then(
        async (result) => {
          await this.host.saveSettings();
          if (result.files.length > 0) {
            new import_obsidian4.Notice(`Rhen Vault restored ${result.files.length} AI guard ${result.files.length === 1 ? "file" : "files"}.`);
          }
        },
        (error) => console.error("Rhen Vault: guard sync failed", error)
      );
    }, 1500);
  }
  /**
   * Catch plaintext that the vault watcher missed. Get-Content, type,
   * File.ReadAllBytes, and StreamReader all read the same bytes; this puts
   * a locked note back to an envelope while Obsidian is open and unlocked.
   */
  async sweepLockedPlaintext() {
    const base = this.host.basePath();
    if (!base || !this.host.installed || this.host.sweeping) return;
    this.host.sweeping = true;
    try {
      let resealed = false;
      for (const file of this.host.app.vault.getFiles()) {
        if (!shouldSeal(file.path, this.host.state)) continue;
        const full = safeJoin(base, file.path);
        if (!full) continue;
        const head = await readHead(full, ENVELOPE_PREFIX.length);
        if (head === null || head === ENVELOPE_PREFIX) {
          this.host.exposedNotice.delete(file.path);
          continue;
        }
        if (!this.host.state.key) {
          if (this.host.exposedNotice.has(file.path)) continue;
          this.host.exposedNotice.add(file.path);
          this.host.toasts.show({
            path: file.path,
            fileName: file.name,
            agentLabel: OUTSIDE,
            action: this.host.userPlaintext.delete(file.path) ? "waiting" : "pending"
          });
          continue;
        }
        if (isAttachmentPath(file.path)) {
          const bytes = await import_fs5.default.promises.readFile(full);
          const sealed2 = resealBytes(file.path, bytes, this.host.state);
          if (!sealed2) continue;
          await this.host.writeDisk(full, sealed2);
          this.host.forgetBlob(file.path);
          this.host.exposedNotice.delete(file.path);
          this.host.toasts.show({ path: file.path, fileName: file.name, agentLabel: OUTSIDE, action: "resealed" });
          resealed = true;
          continue;
        }
        const raw = await import_fs5.default.promises.readFile(full, "utf8");
        const sealed = resealPlaintext(file.path, raw, this.host.state);
        if (!sealed) continue;
        await this.host.writeDisk(full, sealed);
        this.host.exposedNotice.delete(file.path);
        this.host.toasts.show({ path: file.path, fileName: file.name, agentLabel: OUTSIDE, action: "resealed" });
        resealed = true;
      }
      if (resealed) await this.host.refreshOpenNotes();
    } catch (error) {
      console.error("Rhen Vault: plaintext sweep failed", error);
    } finally {
      this.host.sweeping = false;
    }
  }
};

// src/utilities/identity.ts
function asIdentity(value) {
  if (!value || typeof value !== "object") return null;
  const item = value;
  if (typeof item.salt !== "string" || typeof item.verifier !== "string") return null;
  if (typeof item.kdfN !== "number" || typeof item.kdfR !== "number" || typeof item.kdfP !== "number") return null;
  const secretKind = item.secretKind === "image" ? item.secretKind : void 0;
  return {
    salt: item.salt,
    verifier: item.verifier,
    kdfN: item.kdfN,
    kdfR: item.kdfR,
    kdfP: item.kdfP,
    ...secretKind ? { secretKind } : {}
  };
}

// src/windows/exposure.ts
var WRITE_RIGHTS = /* @__PURE__ */ new Set(["F", "M", "W", "D", "WD", "AD", "WA", "DC", "WO"]);
function holdsSessionKey(platform, vaultPath) {
  if (platform !== "win32") return true;
  return vaultPath !== null;
}
function parseIcacls(output, queriedPath) {
  const prefix = queriedPath?.replace(/\//g, "\\").toLowerCase();
  const entries = [];
  for (const raw of output.split(/\r?\n/)) {
    const colon = raw.indexOf(":(");
    if (colon === -1) continue;
    const rights = raw.slice(colon + 1).trim();
    let identity = raw.slice(0, colon).trim();
    if (prefix && identity.toLowerCase().startsWith(prefix)) identity = identity.slice(prefix.length).trim();
    if (!identity) continue;
    entries.push({ identity, rights });
  }
  return entries;
}
function grantsWrite(rights) {
  return [...rights.toUpperCase().matchAll(/\(([^)]*)\)/g)].some((match) => WRITE_RIGHTS.has(match[1]));
}
function isAllowedIdentity(identity, allowed) {
  const id = identity.toLowerCase();
  if (allowed.some((item) => item.toLowerCase() === id)) return true;
  return id === "system" || id === "administrators" || id === "creator owner" || id === "s-1-5-18" || id === "s-1-5-32-544" || id.endsWith("\\system") || id.endsWith("\\administrators") || id.endsWith("\\creator owner");
}
function foreignWriters(entries, allowedIdentities) {
  const found = [];
  for (const entry of entries) {
    if (!grantsWrite(entry.rights) || isAllowedIdentity(entry.identity, allowedIdentities)) continue;
    if (!found.some((item) => item.toLowerCase() === entry.identity.toLowerCase())) found.push(entry.identity);
  }
  return found;
}
function removalCommands(target, writers) {
  const quoted = `"${target}"`;
  return writers.map((writer) => {
    const id = writer.trim();
    const principal = /^S-\d+(-\d+)+$/.test(id) ? `"*${id}"` : `"${id}"`;
    return `icacls ${quoted} /remove ${principal}`;
  }).join("\n");
}

// src/windows/account.ts
var ACCOUNT_NAME = "RhenVault";
var PROTECTED_ROOT = "C:\\RhenVault";
var LEGACY_PROTECTED_ROOT = "C:\\SlateVault";
var SHORTCUT_NAME = "Obsidian (Protected).lnk";
var MAX_COMMAND_LINE = 32e3;
function quote(value) {
  return `'${value.replace(/'/g, "''")}'`;
}
function vaultName(vaultPath) {
  const name = vaultPath.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "";
  if (!name || /[<>:"|?*]/.test(name)) throw new Error(`Unsupported vault folder name: ${name}`);
  return name;
}
function protectedVaultPrefix(root) {
  return `${root.replace(/\//g, "\\").toLowerCase()}\\vaults\\`;
}
function isProtectedPath(basePath, root = PROTECTED_ROOT) {
  const base = basePath.replace(/\//g, "\\").toLowerCase();
  const roots = root === PROTECTED_ROOT ? [PROTECTED_ROOT, LEGACY_PROTECTED_ROOT] : [root];
  return roots.some((candidate) => base.startsWith(protectedVaultPrefix(candidate)));
}
function checked(command, failure) {
  return `${command} | Out-Null; if ($LASTEXITCODE -ne 0) { throw ${quote(failure)} }`;
}
var CLOSE_OBSIDIAN = `function Close-Obsidian {
  $deadline = (Get-Date).AddSeconds(20); $told = $false
  while (Get-Process -Name Obsidian -ErrorAction SilentlyContinue) {
    if ((Get-Date) -lt $deadline) { Get-Process -Name Obsidian -ErrorAction SilentlyContinue | Where-Object MainWindowHandle -ne 0 | ForEach-Object { [void]$_.CloseMainWindow() } }
    elseif (-not $told) { Write-Host 'Close every Obsidian window to continue...' -ForegroundColor Yellow; $told = $true }
    Start-Sleep -Seconds 1
  }
}`;
var EDIT_VAULT_LIST = `function Edit-VaultList($File, $Remove, $Add) {
  try {
    $cfg = $null; if (Test-Path -LiteralPath $File) { $cfg = Get-Content -LiteralPath $File -Raw | ConvertFrom-Json }
    if (-not $cfg) { $cfg = [pscustomobject]@{} }
    if (-not $cfg.vaults) { $cfg | Add-Member -NotePropertyName vaults -NotePropertyValue ([pscustomobject]@{}) -Force }
    foreach ($p in @($cfg.vaults.PSObject.Properties)) { if ($Remove -and $p.Value.path -eq $Remove) { $cfg.vaults.PSObject.Properties.Remove($p.Name) } }
    if ($Add -and -not @($cfg.vaults.PSObject.Properties | Where-Object { $_.Value.path -eq $Add }).Count) {
      $id = -join (1..16 | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
      $cfg.vaults | Add-Member -NotePropertyName $id -NotePropertyValue ([pscustomobject]@{ path = $Add; ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); open = $true })
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -LiteralPath $File) | Out-Null
    [IO.File]::WriteAllText($File, ($cfg | ConvertTo-Json -Depth 10))
  } catch { Write-Host "Could not update $File. Use Obsidian's vault switcher instead." -ForegroundColor Yellow }
}`;
var CLOSE_SOON = `Write-Host 'This window closes in 10 seconds.'; Start-Sleep -Seconds 10`;
var WAIT_FOR_ENTER = `Read-Host 'Press Enter to close'`;
function protectScript(options) {
  const account = options.account ?? ACCOUNT_NAME;
  const root = options.root ?? PROTECTED_ROOT;
  const name = vaultName(options.vaultPath);
  return [
    `$ErrorActionPreference = 'Stop'`,
    CLOSE_OBSIDIAN,
    EDIT_VAULT_LIST,
    `$Account = ${quote(account)}; $Root = ${quote(root)}; $Vault = ${quote(options.vaultPath)}; $AppSource = ${quote(options.obsidianDir)}`,
    `$Dest = Join-Path $Root ${quote(`Vaults\\${name}`)}; $App = Join-Path $Root 'App\\Obsidian'; $Admins = 'S-1-5-32-544'`,
    `Write-Host 'Rhen Vault: moving this vault behind a separate Windows account' -ForegroundColor Cyan`,
    `Write-Host "$Vault -> $Dest"`,
    `Write-Host "Only $Account, SYSTEM, and approved admin sessions will be able to open it. AI tools running as you will not."`,
    `Write-Host 'Close this window now to cancel. Nothing changes until you choose a password.'`,
    `Write-Host 'An Obsidian account is not required. The protected Obsidian starts signed out. Sign in there only if you use Sync.'`,
    `try {`,
    `  if (Test-Path -LiteralPath $Dest) { throw "$Dest already exists." }`,
    `  if (-not (Test-Path -LiteralPath (Join-Path $AppSource 'Obsidian.exe'))) { throw "Obsidian.exe not found in $AppSource" }`,
    `  $user = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue`,
    `  if ($user) { $pw = Read-Host "Password for $Account" -AsSecureString }`,
    `  else {`,
    `    Write-Host "Choose a password for $Account. You type it each time you open the protected vault. Do not let Windows save it."`,
    `    do {`,
    `      $pw = Read-Host 'Password' -AsSecureString; $again = Read-Host 'Same password again' -AsSecureString`,
    `      $same = [Net.NetworkCredential]::new('', $pw).Password -ceq [Net.NetworkCredential]::new('', $again).Password`,
    `      if (-not $same) { Write-Host 'Passwords do not match.' -ForegroundColor Yellow }`,
    `    } until ($same)`,
    `    $user = New-LocalUser -Name $Account -Password $pw -PasswordNeverExpires -AccountNeverExpires -Description 'Rhen Vault protected vault'`,
    `    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user`,
    `  }`,
    `  $sid = $user.SID.Value; $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value`,
    `  $cred = [pscredential]::new("$env:COMPUTERNAME\\$Account", $pw)`,
    `  Write-Host 'Preparing the account...'`,
    `  try { Start-Process -FilePath "$env:WINDIR\\System32\\cmd.exe" -ArgumentList '/c','exit' -WorkingDirectory "$env:WINDIR\\System32" -Credential $cred -LoadUserProfile -WindowStyle Hidden -Wait }`,
    `  catch { throw "Windows did not accept the password for $Account. Nothing was moved." }`,
    `  $userProfile = (Get-CimInstance Win32_UserProfile -Filter "SID='$sid'").LocalPath`,
    `  if (-not $userProfile) { throw "Windows did not create a profile for $Account. Nothing was moved." }`,
    `  Write-Host 'Closing Obsidian...'; Close-Obsidian`,
    `  Write-Host 'Moving the vault...'`,
    `  New-Item -ItemType Directory -Force -Path (Join-Path $Root 'Vaults'), $App | Out-Null`,
    `  ${checked(`& icacls $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' "*\${Admins}:(OI)(CI)F" "*\${sid}:(OI)(CI)M"`, "Setting folder permissions failed.")}`,
    `  & robocopy $AppSource $App /E /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null; if ($LASTEXITCODE -ge 8) { throw 'Copying Obsidian failed.' }`,
    `  Move-Item -LiteralPath $Vault -Destination $Dest`,
    `  @{ restorePath = $Vault; userSid = $me } | ConvertTo-Json | Set-Content -LiteralPath "$Dest.restore.json" -Encoding UTF8`,
    `  ${checked(`& icacls (Join-Path $Root '*') /reset /T /C /Q`, "Resetting permissions inside the protected folder failed.")}`,
    `  ${checked(`& icacls $Root /setowner "*$Admins" /T /C /Q`, "Changing file owners failed.")}`,
    `  $acl = Get-Acl -LiteralPath $Dest`,
    `  $others = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Where-Object { @('S-1-5-18', $Admins, $sid) -notcontains $_ })`,
    `  $owner = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value`,
    `  if ($others.Count -or $owner -ne $Admins) { throw "Permission check failed on $Dest. Run Undo from Rhen Vault before using the vault." }`,
    `  $obsidianData = Join-Path $userProfile 'AppData\\Roaming\\obsidian'`,
    `  Edit-VaultList (Join-Path $obsidianData 'obsidian.json') $null $Dest`,
    `  ${checked(`& icacls $obsidianData /setowner "*$Admins" /T /C /Q`, "Securing the protected account's Obsidian settings failed.")}`,
    `  Edit-VaultList (Join-Path $env:APPDATA 'obsidian\\obsidian.json') $Vault $null`,
    `  $launch = "Start-Process -FilePath '$App\\Obsidian.exe' -WorkingDirectory '$App' -LoadUserProfile -Credential (Get-Credential -UserName '$env:COMPUTERNAME\\$Account' -Message 'Open the Rhen Vault protected vault')"`,
    `  $link = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) ${quote(SHORTCUT_NAME)}))`,
    `  $link.TargetPath = "$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"`,
    `  $link.Arguments = "-NoProfile -WindowStyle Hidden -Command \`"$launch\`""`,
    `  $link.IconLocation = "$App\\Obsidian.exe,0"; $link.Save()`,
    `  Write-Host 'Opening the protected vault...'`,
    `  Start-Process -FilePath "$App\\Obsidian.exe" -WorkingDirectory $App -Credential $cred -LoadUserProfile`,
    `  $pw = $null; $cred = $null`,
    `  Write-Host ''; Write-Host 'Done. Your vault is protected.' -ForegroundColor Green`,
    `  Write-Host "Next time, open it with 'Obsidian (Protected)' on the desktop."`,
    `  ${CLOSE_SOON}`,
    `} catch {`,
    `  Write-Host "Stopped: $($_.Exception.Message)" -ForegroundColor Red`,
    `  if ((Test-Path -LiteralPath $Dest) -and -not (Test-Path -LiteralPath $Vault)) { Write-Host "The vault is at $Dest." }`,
    `  ${WAIT_FOR_ENTER}`,
    `}`
  ].join("\n");
}
function undoScript(protectedPath, account = ACCOUNT_NAME, root = PROTECTED_ROOT) {
  return [
    `$ErrorActionPreference = 'Stop'`,
    CLOSE_OBSIDIAN,
    EDIT_VAULT_LIST,
    `$Dest = ${quote(protectedPath)}; $Account = ${quote(account)}; $Root = ${quote(root)}`,
    `try {`,
    `  $info = Get-Content -LiteralPath "$Dest.restore.json" -Raw | ConvertFrom-Json`,
    `  Write-Host 'Rhen Vault: undo separate-account protection' -ForegroundColor Cyan`,
    `  Write-Host "Moves $Dest back to $($info.restorePath) and gives your normal account access again."`,
    `  Write-Host 'Locked notes stay encrypted. Attachments and everything else become readable to AI tools in that account.' -ForegroundColor Yellow`,
    `  if ((Read-Host 'Type UNDO to continue') -cne 'UNDO') { Write-Host 'Cancelled. Nothing changed.'; ${CLOSE_SOON}; return }`,
    `  if (Test-Path -LiteralPath $info.restorePath) { throw "$($info.restorePath) already exists." }`,
    `  Write-Host 'Closing Obsidian...'; Close-Obsidian`,
    `  Move-Item -LiteralPath $Dest -Destination $info.restorePath`,
    `  ${checked(`& icacls $info.restorePath /setowner "*$($info.userSid)" /T /C /Q`, "Restoring file owners failed.")}`,
    `  ${checked(`& icacls $info.restorePath /reset /T /C /Q`, "Restoring permissions failed.")}`,
    `  Remove-Item -LiteralPath "$Dest.restore.json"`,
    `  $user = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue`,
    `  if ($user) {`,
    `    $userProfile = (Get-CimInstance Win32_UserProfile -Filter "SID='$($user.SID.Value)'").LocalPath`,
    `    if ($userProfile) { Edit-VaultList (Join-Path $userProfile 'AppData\\Roaming\\obsidian\\obsidian.json') $Dest $null }`,
    `  }`,
    `  Edit-VaultList (Join-Path $env:APPDATA 'obsidian\\obsidian.json') $null $info.restorePath`,
    `  Write-Host ''; Write-Host "Done. Open Obsidian normally to use $($info.restorePath)." -ForegroundColor Green`,
    `  Write-Host "The $Account account, $Root, and the desktop shortcut are still there. Remove them when no other vault uses them:"`,
    `  Write-Host "  Remove-LocalUser $Account; Remove-Item '$Root' -Recurse -Force; Remove-Item (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) ${quote(SHORTCUT_NAME)})"`,
    `  ${WAIT_FOR_ENTER}`,
    `} catch {`,
    `  Write-Host "Stopped: $($_.Exception.Message)" -ForegroundColor Red`,
    `  ${WAIT_FOR_ENTER}`,
    `}`
  ].join("\n");
}
function elevatedLaunchArgs(script) {
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  const command = `Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','${encoded}'`;
  if (command.length > MAX_COMMAND_LINE) throw new Error("Setup script is too long for a Windows command line.");
  return ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", command];
}

// src/main.ts
var LOCK_RECORD_STORAGE = "rhen-vault-lock-record";
var IDENTITY_STORAGE = "rhen-vault-identity";
var RECOVERY_MARK = "rhen-vault-v1";
var LEGACY_LOCK_RECORD_STORAGE = "slate-infosec-lock-record";
var LEGACY_IDENTITY_STORAGE = "slate-infosec-identity";
var LEGACY_RECOVERY_MARK = "slate-infosec-v1";
var LEGACY_PLUGIN_ID = "slate-infosec";
var RhenVaultPlugin = class extends import_obsidian5.Plugin {
  settings = mergeSettings(null);
  state = {
    key: null,
    extensions: ["md", "txt", "canvas"],
    configDir: "",
    blockedPluginIds: ["realclaudian"],
    lockedFiles: [],
    lockedFolders: [],
    unlockedFiles: [],
    unlockedFolders: []
  };
  installed = null;
  statusEl = null;
  lastLockedNotice = 0;
  lastCorruptNotice = 0;
  lastDecryptNotice = 0;
  adapterDepth = 0;
  sealingDisk = false;
  protectionStarted = false;
  sweeping = false;
  exposedNotice = /* @__PURE__ */ new Set();
  userPlaintext = /* @__PURE__ */ new Set();
  toasts = new AccessToasts(document);
  restoreFs = null;
  restoreResourcePath = null;
  blobUrls = /* @__PURE__ */ new Map();
  watchedAgents = [];
  inspecting = /* @__PURE__ */ new Set();
  reinspect = /* @__PURE__ */ new Set();
  guardSyncTimer = null;
  media = new MediaStore(this);
  watch = new VaultWatch(this);
  filesystem = new FilesystemGuard(this);
  lockActions = new LockActions(this);
  guards = new GuardSync(this);
  async onload() {
    let loaded = await this.loadData();
    if (!mergeSettings(loaded).verifier) {
      const legacy = await this.readLegacyPluginData();
      if (legacy) {
        loaded = legacy;
        await this.saveData(legacy);
        new import_obsidian5.Notice("Rhen Vault imported settings from the former Slate plugin.");
      }
    }
    this.settings = mergeSettings(loaded);
    this.state = {
      key: null,
      extensions: this.settings.extensions,
      configDir: this.app.vault.configDir,
      blockedPluginIds: blockedPluginIds(this.settings),
      lockedFiles: this.settings.lockedFiles,
      lockedFolders: this.settings.lockedFolders,
      unlockedFiles: this.settings.unlockedFiles,
      unlockedFolders: this.settings.unlockedFolders
    };
    this.installed = installSealAdapter(this.app.vault.adapter, this.state, {
      onLocked: () => this.noticeLocked(),
      onCorrupt: (filePath) => this.noticeCorruptSave(filePath),
      onAgentAccess: (filePath, agentId, action) => this.reportAgentAccess(filePath, agentId, action),
      onUserPlaintext: (filePath) => {
        this.userPlaintext.add(filePath);
      },
      begin: () => {
        this.adapterDepth += 1;
      },
      end: () => {
        this.adapterDepth = Math.max(0, this.adapterDepth - 1);
      }
    });
    try {
      this.installFsProbe();
    } catch (error) {
      console.error("Rhen Vault: fs read probe unavailable", error);
    }
    this.installResourcePaths();
    this.registerFileMenus();
    this.registerWatchers();
    this.addRibbonIcon("lock", "Rhen Vault", () => {
      if (this.state.key) this.lock();
      else this.openUnlockOrSetup();
    });
    this.statusEl = this.addStatusBarItem();
    this.addSettingTab(new RhenVaultSettingTab(this.app, this));
    this.addCommands();
    this.registerInterval(window.setInterval(() => {
      this.enforceAgentBoundary();
      void this.sweepLockedPlaintext();
    }, 1e3));
    this.enforceAgentBoundary();
    this.renderStatus();
    this.disableFileRecovery();
    void this.syncHarnessGuards().then(() => this.saveSettings()).catch(() => void 0);
    this.app.workspace.onLayoutReady(() => this.beginForThisComputer());
  }
  /** Runs after the vault path exists. Opens setup or unlock. Signed-in and signed-out Obsidian users take the same path. */
  beginForThisComputer() {
    if (!this.settings.verifier) {
      new import_obsidian5.Notice("Rhen Vault is on. Set a passphrase, then right-click a note or folder and choose Lock from AI.");
      this.openSetup();
    } else if (!this.isUnlocked()) {
      this.openUnlock();
    }
  }
  onunload() {
    if (this.guardSyncTimer !== null) window.clearTimeout(this.guardSyncTimer);
    this.flushOpenEditorsToDisk();
    wipeKey(this.state.key);
    this.state.key = null;
    this.restoreFs?.();
    this.restoreFs = null;
    this.restoreResourcePath?.();
    this.restoreResourcePath = null;
    this.revokeBlobUrls();
    this.toasts.destroy();
    this.installed?.restore();
    this.installed = null;
  }
  isUnlocked() {
    return this.state.key !== null;
  }
  agentBlockLabels() {
    return this.watchedAgents.map(labelForPlugin);
  }
  openSetup() {
    new SetupModal(this.app, this.basePath(), (choice) => {
      void this.setup(choice);
    }).open();
  }
  openUnlock() {
    if (this.sessionBlocked()) {
      this.confirmAccountProtection();
      return;
    }
    void this.foreignPluginWriters().then((writers) => {
      if (writers.length > 0) {
        this.refuseExposed(
          `Rhen Vault will not unlock. ${writers.join(", ")} can change this plugin and capture the passphrase. Open Settings \u2192 Rhen Vault \u2192 Plugin file protection to fix it.`
        );
        this.showExposureInfo(writers);
        return;
      }
      const salt = this.settings.salt ? new Uint8Array(Buffer.from(this.settings.salt, "base64")) : null;
      new UnlockModal(this.app, this.settings.secretKind, this.basePath(), salt, (secret) => {
        if (this.unlock(secret)) new import_obsidian5.Notice("Rhen Vault unlocked. Locked notes stay encrypted on disk.");
      }).open();
    });
  }
  openUnlockOrSetup() {
    if (this.sessionBlocked()) {
      this.confirmAccountProtection();
      return;
    }
    if (this.settings.verifier) this.openUnlock();
    else this.openSetup();
  }
  lock() {
    this.flushOpenEditorsToDisk();
    wipeKey(this.state.key);
    this.state.key = null;
    this.revokeBlobUrls();
    void this.refreshOpenNotes();
    this.renderStatus();
  }
  async sealAll() {
    this.requireKey();
    const installed = this.requireInstalled();
    const key = this.state.key;
    let count = 0;
    for (const file of this.app.vault.getFiles()) {
      if (!shouldSeal(file.path, this.state)) continue;
      if (isAttachmentPath(file.path)) {
        if (await this.sealAttachment(file.path, key)) count += 1;
        continue;
      }
      const raw = await installed.read(file.path);
      if (isEnvelope(raw)) continue;
      await installed.write(file.path, encryptWithKey(raw, key));
      count += 1;
    }
    await this.refreshOpenNotes();
    return count;
  }
  async unsealAll() {
    this.requireKey();
    const installed = this.requireInstalled();
    const opened = [];
    for (const file of this.app.vault.getFiles()) {
      if (!shouldSeal(file.path, this.state)) continue;
      if (isAttachmentPath(file.path)) {
        const full = this.diskPath(file.path);
        if (!full) continue;
        const bytes = await import_fs6.default.promises.readFile(full);
        if (!isEnvelopeBytes(bytes)) continue;
        const plain2 = openBytes(bytes, this.state.key);
        if (plain2 === null) throw new Error("decrypt failed");
        opened.push({ path: file.path, plain: plain2 });
        continue;
      }
      const raw = await installed.read(file.path);
      if (!isEnvelope(raw)) continue;
      const plain = decryptWithKey(raw, this.state.key);
      if (plain === null) throw new Error("decrypt failed");
      opened.push({ path: file.path, plain });
    }
    this.commitRules({ lockedFiles: [], lockedFolders: [], unlockedFiles: [], unlockedFolders: [] });
    await this.saveSettings();
    let count = 0;
    for (const file of opened) {
      if (typeof file.plain === "string") {
        await installed.write(file.path, file.plain);
      } else {
        const full = this.diskPath(file.path);
        if (!full) continue;
        await this.writeDisk(full, file.plain);
        this.forgetBlob(file.path);
      }
      count += 1;
    }
    await this.refreshOpenNotes();
    await this.syncHarnessGuards();
    await this.saveSettings();
    return count;
  }
  async writeShields() {
    const installed = this.requireInstalled();
    const written = [];
    const skipped = [];
    for (const file of PROSE_FILES) {
      let current = null;
      try {
        current = await installed.read(file.path);
      } catch {
        current = null;
      }
      if (current !== null && !current.includes(SHIELD_MARKER) && !current.includes(LEGACY_SHIELD_MARKER)) {
        skipped.push(file.path);
        continue;
      }
      await installed.write(file.path, file.contents);
      written.push(file.path);
    }
    const guards = await this.syncHarnessGuards();
    for (const path3 of guards.files) {
      if (!written.includes(path3)) written.push(path3);
    }
    if (written.length > 0) this.settings.shieldsWritten = true;
    await this.saveSettings();
    return { written, skipped };
  }
  async saveSettings() {
    this.syncSealState();
    if (this.state.key) {
      this.settings.lockRecord = sealLockRecord(this.lockRecord(), this.state.key);
      this.app.saveLocalStorage(LOCK_RECORD_STORAGE, this.settings.lockRecord);
      const identity = this.identity();
      if (identity) this.app.saveLocalStorage(IDENTITY_STORAGE, identity);
    }
    await this.saveData(this.settings);
  }
  addCommands() {
    this.addCommand({
      id: "unlock",
      name: "Unlock",
      callback: () => this.openUnlockOrSetup()
    });
    this.addCommand({
      id: "lock",
      name: "Lock session",
      callback: () => this.lock()
    });
    this.addCommand({
      id: "lock-active",
      name: "Lock current file from AI",
      checkCallback: (checking) => {
        const file = this.app.workspace.getActiveFile();
        if (!file) return false;
        if (!checking) void this.lockSelection([file]);
        return true;
      }
    });
    this.addCommand({
      id: "unlock-active",
      name: "Unlock current file from AI",
      checkCallback: (checking) => {
        const file = this.app.workspace.getActiveFile();
        if (!file || !isLockedPath(file.path, this.rules())) return false;
        if (!checking) void this.unlockSelection([file]);
        return true;
      }
    });
    this.addCommand({
      id: "seal",
      name: "Seal unsealed notes",
      callback: () => {
        void this.sealAll().then(
          (count) => new import_obsidian5.Notice(count === 0 ? "No plaintext notes to seal." : `Sealed ${count} notes.`),
          () => new import_obsidian5.Notice("Unlock Rhen Vault before sealing notes.")
        );
      }
    });
    this.addCommand({
      id: "shields",
      name: "Write agent shield files",
      callback: () => {
        void this.writeShields().then((result) => {
          new import_obsidian5.Notice(`Wrote ${result.written.length} shield files.`);
        });
      }
    });
    this.addCommand({
      id: "sync-guards",
      name: "Sync AI guard files for locked notes",
      callback: () => {
        void this.syncHarnessGuards().then(
          (result) => {
            void this.saveSettings();
            new import_obsidian5.Notice(
              result.files.length === 0 ? "Guard files match the lock list." : `Synced ${result.files.length} guard files.`
            );
          },
          () => new import_obsidian5.Notice("Rhen Vault could not sync guard files.")
        );
      }
    });
    this.addCommand({
      id: "copy-codex-rules",
      name: "Copy Codex deny rules for locked notes",
      callback: () => {
        void navigator.clipboard.writeText(this.codexRules()).then(
          () => new import_obsidian5.Notice("Copied. Paste into ~/.codex/config.toml under your profile's filesystem table."),
          () => new import_obsidian5.Notice("Rhen Vault could not copy to the clipboard.")
        );
      }
    });
    this.addCommand({
      id: "protect-with-windows-account",
      name: "Protect this vault with a separate Windows account",
      checkCallback: (checking) => {
        if (!this.canUseAccountProtection() || this.isAccountProtected()) return false;
        if (!checking) this.confirmAccountProtection();
        return true;
      }
    });
    this.addCommand({
      id: "undo-windows-account",
      name: "Undo separate Windows account protection",
      checkCallback: (checking) => {
        if (!this.isAccountProtected()) return false;
        if (!checking) this.confirmAccountUndo();
        return true;
      }
    });
    this.addCommand({
      id: "recovery-info",
      name: "Show recovery and safe uninstall steps",
      callback: () => this.showRecoveryInfo()
    });
    this.addCommand({
      id: "check-protection",
      name: "Check plugin file protection",
      callback: () => {
        void this.checkPluginWriters().then((writers) => {
          if (writers.length > 0) this.showExposureInfo(writers);
          else new import_obsidian5.Notice("Only you, SYSTEM, and administrators can change the plugin files.");
        });
      }
    });
    this.addCommand({
      id: "unseal",
      name: "Unseal notes to plaintext",
      callback: () => {
        new ConfirmModal(
          this.app,
          {
            title: "Unseal notes?",
            body: "This writes note text back to disk as plaintext. Local AI agents will be able to read them.",
            confirm: "Unseal"
          },
          () => {
            void this.unsealAll().then(
              (count) => new import_obsidian5.Notice(`Unsealed ${count} notes.`),
              () => new import_obsidian5.Notice("Unlock Rhen Vault before unsealing notes.")
            );
          }
        ).open();
      }
    });
  }
  async setup(choice) {
    if (this.settings.verifier) {
      new import_obsidian5.Notice("This vault already has a Rhen Vault secret.");
      return;
    }
    const salt = Buffer.from(choice.salt ?? crypto.getRandomValues(new Uint8Array(16)));
    const key = deriveKey(choice.secret, salt, {
      N: this.settings.kdfN,
      r: this.settings.kdfR,
      p: this.settings.kdfP
    });
    this.settings.salt = salt.toString("base64");
    this.settings.verifier = createVerifier(key);
    this.settings.secretKind = choice.kind;
    this.state.key = key;
    await this.saveSettings();
    if (choice.shields) await this.writeShields();
    if (this.sessionBlocked()) {
      this.refuseExposed("Secret saved. Rhen Vault will not unlock this vault until it is on the protected Windows account.");
      this.confirmAccountProtection();
      return;
    }
    new import_obsidian5.Notice("Rhen Vault secret saved. Right-click a note or folder and choose Lock from AI.");
    this.renderStatus();
    this.maybeShowRecoveryNotice();
  }
  unlock(passphrase) {
    const current = this.identity();
    const backup = asIdentity(this.app.loadLocalStorage(IDENTITY_STORAGE)) ?? asIdentity(this.app.loadLocalStorage(LEGACY_IDENTITY_STORAGE));
    const candidates = [current, backup && backup.salt !== current?.salt ? backup : null];
    for (const identity of candidates) {
      if (!identity) continue;
      const key = deriveKey(passphrase, Buffer.from(identity.salt, "base64"), {
        N: identity.kdfN,
        r: identity.kdfR,
        p: identity.kdfP
      });
      if (!verifierMatches(identity.verifier, key)) {
        wipeKey(key);
        continue;
      }
      if (identity !== current) {
        Object.assign(this.settings, identity);
        new import_obsidian5.Notice("Rhen Vault's passphrase settings were changed outside Obsidian. Rhen Vault restored them from its backup.");
      }
      if (this.sessionBlocked()) {
        wipeKey(key);
        this.refuseExposed("Rhen Vault will not unlock this vault. Move it to the protected Windows account first.");
        return false;
      }
      wipeKey(this.state.key);
      this.state.key = key;
      void this.refreshOpenNotes();
      this.renderStatus();
      void this.afterUnlock(key).catch((error) => console.error("Rhen Vault: post-unlock checks failed", error));
      this.maybeShowRecoveryNotice();
      return true;
    }
    new import_obsidian5.Notice("Wrong passphrase.");
    return false;
  }
  /**
   * Verify the lock list against the sealed record in plugin data and the
   * copy in Obsidian's local storage, restore anything removed outside
   * Rhen Vault, then encrypt any locked note that is still plaintext.
   */
  async afterUnlock(key) {
    let record = this.lockRecord();
    let tampered = false;
    for (const stored of [
      this.settings.lockRecord,
      this.app.loadLocalStorage(LOCK_RECORD_STORAGE),
      this.app.loadLocalStorage(LEGACY_LOCK_RECORD_STORAGE)
    ]) {
      if (typeof stored !== "string" || !stored) continue;
      const trusted = openLockRecord(stored, key);
      if (!trusted) {
        tampered = true;
        continue;
      }
      const merged = reconcileRecord(record, trusted);
      record = merged.record;
      tampered ||= merged.tampered;
    }
    if (tampered) {
      this.commitRules(record.rules);
      this.settings.extensions = record.extensions;
      this.settings.extraBlockedPluginIds = record.extraBlockedPluginIds;
    }
    await this.saveSettings();
    if (tampered) {
      new import_obsidian5.Notice("Rhen Vault's lock list was changed outside Obsidian. Rhen Vault restored its locks.");
      await this.syncHarnessGuards();
      await this.saveSettings();
    }
    const count = await this.sealAll();
    if (count > 0) {
      new import_obsidian5.Notice(`Rhen Vault encrypted ${count} locked ${count === 1 ? "note that was" : "notes that were"} still plaintext.`);
    }
    const unreadable = await this.scanUnreadableLocked();
    if (unreadable > 0) {
      new import_obsidian5.Notice(
        unreadable === 1 ? "One locked note cannot be decrypted with this secret. It may be damaged or sealed under a different secret. The lock stays on. Restore that note from backup." : `${unreadable} locked notes cannot be decrypted with this secret. Locks stay on. Restore those notes from backup.`
      );
    }
  }
  /**
   * Plugin data edited outside Obsidian while it runs. The in-memory copy is
   * authoritative: outside edits may add locks, never remove them, and never
   * replace the passphrase settings.
   */
  async onExternalSettingsChange() {
    const loaded = mergeSettings(await this.loadData());
    const before = this.lockRecord();
    const merged = reconcileRecord(
      {
        rules: {
          lockedFiles: loaded.lockedFiles,
          lockedFolders: loaded.lockedFolders,
          unlockedFiles: loaded.unlockedFiles,
          unlockedFolders: loaded.unlockedFolders
        },
        extensions: loaded.extensions,
        extraBlockedPluginIds: loaded.extraBlockedPluginIds
      },
      before
    );
    const identityChanged = loaded.salt !== this.settings.salt || loaded.verifier !== this.settings.verifier || loaded.lockRecord !== this.settings.lockRecord;
    this.commitRules(merged.record.rules);
    this.settings.extensions = merged.record.extensions;
    this.settings.extraBlockedPluginIds = merged.record.extraBlockedPluginIds;
    await this.saveSettings();
    this.scheduleGuardSync();
    if (merged.tampered || identityChanged) {
      new import_obsidian5.Notice("Rhen Vault's settings were changed outside Obsidian. Rhen Vault kept its locks.");
    }
  }
  /**
   * One-time uninstall notice, shown after setup and on the next unlock for
   * upgraders. The ack lives in settings, so a reinstall (which wipes
   * settings) shows it again. There is no Cancel: the point is that this
   * gets read before any lock can strand ciphertext. The same copy stays
   * available on demand through showRecoveryInfo (Settings button and
   * command palette), so the once-only ack never strands the information.
   */
  maybeShowRecoveryNotice() {
    if (!this.settings.verifier || this.settings.recoveryNoticeAck) return;
    this.showRecoveryInfo();
  }
  /** Reopen the safe-uninstall and recovery steps on demand. Never strands the ack. */
  showRecoveryInfo() {
    new UninstallNoticeModal(this.app, this, () => {
      this.settings.recoveryNoticeAck = true;
      void this.saveSettings();
    }).open();
  }
  /** Settings left in the former Slate plugin folder after a rename to Rhen Vault. */
  async readLegacyPluginData() {
    const adapter = this.app.vault.adapter;
    const legacyPath = `${this.app.vault.configDir}/plugins/${LEGACY_PLUGIN_ID}/data.json`;
    try {
      if (!await adapter.exists(legacyPath)) return null;
      const raw = await adapter.read(legacyPath);
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") return null;
      const legacy = parsed;
      return legacy.verifier ? legacy : null;
    } catch (error) {
      console.error("Rhen Vault: could not read legacy plugin data", error);
      return null;
    }
  }
  identity() {
    const { salt, verifier, kdfN, kdfR, kdfP, secretKind } = this.settings;
    return salt && verifier ? { salt, verifier, kdfN, kdfR, kdfP, secretKind } : null;
  }
  /**
   * Locked files whose envelopes the session key cannot open. Text reads go
   * through the raw adapter; attachments are read as bytes from disk.
   * Missing files are ignored; only undecryptable envelopes count.
   */
  async scanUnreadableLocked() {
    const key = this.state.key;
    const installed = this.installed;
    if (!key || !installed) return 0;
    let count = 0;
    for (const file of this.app.vault.getFiles()) {
      if (!shouldSeal(file.path, this.state)) continue;
      try {
        if (isAttachmentPath(file.path)) {
          const full = this.diskPath(file.path);
          if (!full) continue;
          const bytes = await import_fs6.default.promises.readFile(full);
          if (isEnvelopeBytes(bytes) && openBytes(bytes, key) === null) count += 1;
        } else {
          const raw = await installed.read(file.path);
          if (isEnvelope(raw) && decryptWithKey(raw, key) === null) count += 1;
        }
      } catch {
      }
    }
    return count;
  }
  /**
   * Recovery file contents: salt, verifier, and KDF parameters. Never the
   * secret or the key. Importing it after a reinstall lets the same
   * passphrase derive the old key again, because uninstalling deletes the
   * salt from plugin data. Anyone holding this file can still test
   * passphrase guesses offline, exactly like plugin data.
   */
  exportRecovery() {
    const identity = this.identity();
    if (!identity) return null;
    return JSON.stringify({ recovery: RECOVERY_MARK, exportedAt: (/* @__PURE__ */ new Date()).toISOString(), ...identity }, null, 2);
  }
  /** Restore salt, verifier, and KDF parameters from a recovery file. False when the shape is wrong. */
  async importRecoveryFile(data) {
    if (!data || typeof data !== "object") return false;
    if (data.recovery !== RECOVERY_MARK && data.recovery !== LEGACY_RECOVERY_MARK) return false;
    const identity = asIdentity(data);
    if (!identity) return false;
    Object.assign(this.settings, identity);
    await this.saveSettings();
    return true;
  }
  lockRecord() {
    return {
      rules: this.rules(),
      extensions: [...this.settings.extensions],
      extraBlockedPluginIds: [...this.settings.extraBlockedPluginIds]
    };
  }
  enforceAgentBoundary() {
    this.watchedAgents = this.enabledBlockedIds();
    this.syncSealState();
    this.renderStatus();
  }
  enabledBlockedIds() {
    const enabled = this.enabledPluginIds();
    return blockedPluginIds(this.settings).filter((id) => enabled.has(id));
  }
  enabledPluginIds() {
    const host = this.app;
    const raw = host.plugins?.enabledPlugins;
    return new Set(raw ? raw : []);
  }
  async refreshOpenNotes() {
    const installed = this.installed;
    if (!installed) return;
    const views = [];
    this.app.workspace.iterateAllLeaves((leaf) => {
      if (leaf.view instanceof import_obsidian5.MarkdownView && leaf.view.file) views.push(leaf.view);
    });
    const unreadable = [];
    for (const view of views) {
      const file = view.file;
      if (!file) continue;
      try {
        const raw = await installed.read(file.path);
        if (this.state.key && shouldSeal(file.path, this.state) && isEnvelope(raw) && decryptWithKey(raw, this.state.key) === null) {
          unreadable.push(file.path);
        }
        view.setViewData(incoming(raw, file.path, this.state), true);
      } catch {
      }
    }
    if (unreadable.length > 0) this.noticeDecryptFailed(unreadable);
  }
  flushOpenEditorsToDisk() {
    const base = this.basePath();
    const key = this.state.key;
    if (!base || !key) return;
    this.app.workspace.iterateAllLeaves((leaf) => {
      const view = leaf.view;
      if (!(view instanceof import_obsidian5.MarkdownView) || !view.file || !view.editor) return;
      if (!shouldSeal(view.file.path, this.state)) return;
      const current = view.editor.getValue();
      if (isEnvelope(current) && decryptWithKey(current, key) === null) return;
      const sealed = isEnvelope(current) ? current : encryptWithKey(current, key);
      const full = safeJoin(base, view.file.path);
      if (!full) return;
      import_fs6.default.writeFileSync(full, sealed, { encoding: "utf8" });
      view.setViewData(sealed, true);
    });
  }
  basePath() {
    const adapter = this.app.vault.adapter;
    if (adapter instanceof import_obsidian5.FileSystemAdapter) return adapter.getBasePath();
    return null;
  }
  noticeLocked() {
    const now = Date.now();
    if (now - this.lastLockedNotice < 3e3) return;
    this.lastLockedNotice = now;
    new import_obsidian5.Notice("Unlock Rhen Vault before editing a locked note.");
  }
  noticeCorruptSave(filePath) {
    const now = Date.now();
    if (now - this.lastCorruptNotice < 1e4) return;
    this.lastCorruptNotice = now;
    new import_obsidian5.Notice(
      `Rhen Vault refused to save ${filePath}: its envelope cannot be opened with this secret. Restore that note from backup.`
    );
  }
  noticeDecryptFailed(paths) {
    const now = Date.now();
    if (now - this.lastDecryptNotice < 1e4) return;
    this.lastDecryptNotice = now;
    new import_obsidian5.Notice(
      paths.length === 1 ? `Rhen Vault could not decrypt ${paths[0]} with this secret. It may be damaged or sealed under a different secret. The lock stays on.` : `Rhen Vault could not decrypt ${paths.length} locked notes with this secret. Locks stay on. Restore those notes from backup.`
    );
  }
  sessionBlocked() {
    return !holdsSessionKey(process.platform, this.basePath());
  }
  refuseExposed(message) {
    wipeKey(this.state.key);
    this.state.key = null;
    void this.refreshOpenNotes();
    this.renderStatus();
    new import_obsidian5.Notice(message);
  }
  foreignPluginWriters() {
    if (process.platform !== "win32") return Promise.resolve([]);
    const base = this.basePath();
    if (!base) return Promise.resolve([]);
    const pluginDir = path2.join(base, this.app.vault.configDir, "plugins", this.manifest.id);
    const target = import_fs6.default.existsSync(pluginDir) ? pluginDir : base;
    const user = [process.env.USERDOMAIN, process.env.USERNAME].filter(Boolean).join("\\");
    return new Promise((resolve2) => {
      (0, import_child_process.execFile)("icacls", [target], { windowsHide: true, timeout: 8e3 }, (error, stdout) => {
        if (error) {
          console.error("Rhen Vault: could not read plugin permissions", error);
          resolve2([]);
          return;
        }
        resolve2(foreignWriters(parseIcacls(stdout, target), user ? [user] : []));
      });
    });
  }
  /** Accounts, other than you and Windows itself, that can rewrite the plugin. Empty when the check cannot run. */
  checkPluginWriters() {
    return this.foreignPluginWriters();
  }
  /** Folder the permission check reads, for the copyable fix. Null when the vault path is unknown. */
  pluginTargetPath() {
    const base = this.basePath();
    if (!base) return null;
    const pluginDir = path2.join(base, this.app.vault.configDir, "plugins", this.manifest.id);
    return import_fs6.default.existsSync(pluginDir) ? pluginDir : base;
  }
  /** The refusal explained, with fixes. Re-checking re-runs unlock, which passes once the writers are gone. */
  showExposureInfo(writers) {
    const target = this.pluginTargetPath();
    new ExposureModal(
      this.app,
      {
        writers,
        target,
        fixCommands: target ? removalCommands(target, writers) : null,
        canProtect: this.canUseAccountProtection() && !this.isAccountProtected()
      },
      {
        onProtect: () => this.confirmAccountProtection(),
        onRecheck: () => this.openUnlockOrSetup()
      }
    ).open();
  }
  disableFileRecovery() {
    const host = this.app;
    const recovery = host.internalPlugins?.getPluginById?.("file-recovery");
    if (!recovery?.enabled) return;
    if (!recovery.disable) {
      new import_obsidian5.Notice("Rhen Vault: File recovery is on. Turn it off under Core plugins. It can store plaintext snapshots.");
      return;
    }
    try {
      recovery.disable();
      new import_obsidian5.Notice("Rhen Vault turned off File recovery so it cannot keep plaintext snapshots.");
    } catch (error) {
      console.error("Rhen Vault: could not turn off File recovery", error);
      new import_obsidian5.Notice("Rhen Vault: File recovery is on. Turn it off under Core plugins. It can store plaintext snapshots.");
    }
  }
  renderStatus() {
    if (!this.statusEl) return;
    const watching = this.watchedAgents.length ? ` \xB7 ${this.watchedAgents.map(labelForPlugin).join(", ")}` : "";
    if (this.sessionBlocked()) this.statusEl.setText("Rhen Vault: protected account required");
    else if (!this.settings.verifier) this.statusEl.setText("Rhen Vault: set a passphrase");
    else if (this.state.key) this.statusEl.setText(`Rhen Vault: open${watching}`);
    else this.statusEl.setText(`Rhen Vault: session locked${watching}`);
  }
  requireKey() {
    if (!this.state.key) throw new SealLockedError("");
  }
  requireInstalled() {
    if (!this.installed) throw new SealLockedError("");
    return this.installed;
  }
  syncSealState() {
    this.state.extensions = this.settings.extensions;
    this.state.configDir = this.app.vault.configDir;
    this.state.blockedPluginIds = blockedPluginIds(this.settings);
    this.state.lockedFiles = this.settings.lockedFiles;
    this.state.lockedFolders = this.settings.lockedFolders;
    this.state.unlockedFiles = this.settings.unlockedFiles;
    this.state.unlockedFolders = this.settings.unlockedFolders;
  }
  rules() {
    return {
      lockedFiles: this.settings.lockedFiles,
      lockedFolders: this.settings.lockedFolders,
      unlockedFiles: this.settings.unlockedFiles,
      unlockedFolders: this.settings.unlockedFolders
    };
  }
  commitRules(rules) {
    this.settings.lockedFiles = [...rules.lockedFiles];
    this.settings.lockedFolders = [...rules.lockedFolders];
    this.settings.unlockedFiles = [...rules.unlockedFiles];
    this.settings.unlockedFolders = [...rules.unlockedFolders];
    this.syncSealState();
  }
  observe(ref) {
    this.registerEvent(ref);
  }
  registerFileMenus() {
    this.lockActions.register();
  }
  lockSelection(files) {
    return this.lockActions.lockSelection(files);
  }
  unlockSelection(files) {
    return this.lockActions.unlockSelection(files);
  }
  registerWatchers() {
    this.watch.register();
  }
  scheduleGuardSync() {
    this.watch.scheduleGuardSync();
  }
  sweepLockedPlaintext() {
    return this.watch.sweepLockedPlaintext();
  }
  syncHarnessGuards() {
    return this.guards.sync();
  }
  installResourcePaths() {
    this.media.installResourcePaths();
  }
  revokeBlobUrls() {
    this.media.revokeBlobUrls();
  }
  forgetBlob(vaultPath) {
    this.media.forgetBlob(vaultPath);
  }
  diskPath(vaultPath) {
    return this.media.diskPath(vaultPath);
  }
  sealAttachment(vaultPath, key) {
    return this.media.sealAttachment(vaultPath, key);
  }
  openAttachment(vaultPath, key) {
    return this.media.openAttachment(vaultPath, key);
  }
  writeDisk(full, data) {
    return this.media.writeDisk(full, data);
  }
  installFsProbe() {
    this.filesystem.install();
  }
  codexRules() {
    return codexSnippet(this.rules());
  }
  canUseAccountProtection() {
    return process.platform === "win32" && this.basePath() !== null;
  }
  isAccountProtected() {
    const base = this.basePath();
    return process.platform === "win32" && base !== null && isProtectedPath(base);
  }
  confirmAccountProtection() {
    const base = this.basePath();
    if (process.platform !== "win32" || base === null || this.isAccountProtected()) return;
    if (this.protectionStarted) return;
    this.protectionStarted = true;
    this.runElevated(protectScript({ vaultPath: base, obsidianDir: path2.dirname(process.execPath) }));
  }
  confirmAccountUndo() {
    const base = this.basePath();
    if (!this.isAccountProtected() || base === null) return;
    new ConfirmModal(
      this.app,
      {
        title: "Undo separate-account protection?",
        body: "Windows will ask for an administrator's password. The vault moves back to where it was, and your normal account gets access again. Locked notes stay encrypted. Everything else becomes readable to AI tools in that account.",
        confirm: "Open undo"
      },
      () => this.runElevated(undoScript(base))
    ).open();
  }
  runElevated(script) {
    try {
      const child = (0, import_child_process.spawn)("powershell.exe", elevatedLaunchArgs(script), {
        detached: true,
        stdio: "ignore",
        windowsHide: true
      });
      child.on("error", () => new import_obsidian5.Notice("Rhen Vault could not start PowerShell."));
      child.unref();
      new import_obsidian5.Notice(`Approve the Windows prompt, then choose a password for ${ACCOUNT_NAME}. Nothing moves until Windows accepts it.`);
    } catch (error) {
      console.error("Rhen Vault: elevated setup failed to start", error);
      new import_obsidian5.Notice("Rhen Vault could not start the setup window.");
    }
  }
  reportAgentAccess(filePath, agentId, action) {
    const name = filePath.slice(filePath.lastIndexOf("/") + 1);
    this.toasts.show({
      path: filePath,
      fileName: name,
      agentLabel: labelForPlugin(agentId),
      action
    });
  }
};
