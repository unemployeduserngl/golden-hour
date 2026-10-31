const fs = require("node:fs");
const path = require("node:path");

const BLOCK_THRESHOLD = 70;
const DEFAULT_FILE = path.join(__dirname, "..", "data", "blocklist.json");

function isValidDomain(domain) {
  return typeof domain === "string" &&
    domain.length <= 253 &&
    domain.includes(".") &&
    domain.split(".").every((label) =>
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)
    );
}

function createBlocklist(filePath = DEFAULT_FILE) {
  function readEntries() {
    try {
      const value = JSON.parse(fs.readFileSync(filePath, "utf8"));
      return Array.isArray(value) ? value.filter((entry) =>
        entry && isValidDomain(entry.domain) &&
        typeof entry.addedAt === "string" &&
        Number.isInteger(entry.score) && entry.score >= BLOCK_THRESHOLD && entry.score <= 100
      ) : [];
    } catch (error) {
      if (error.code === "ENOENT") return [];
      throw new Error("The local blocklist could not be read.");
    }
  }

  function writeEntries(entries) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const temporaryFile = `${filePath}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryFile, `${JSON.stringify(entries, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporaryFile, filePath);
  }

  return {
    list: readEntries,
    find(domain) {
      const normalized = domain.toLowerCase().replace(/\.$/, "");
      if (!isValidDomain(normalized)) return null;
      return readEntries().find((entry) =>
        normalized === entry.domain || normalized.endsWith(`.${entry.domain}`)
      ) || null;
    },
    add(domain, score, reason) {
      const normalized = domain.toLowerCase().replace(/\.$/, "");
      if (!isValidDomain(normalized) || !Number.isInteger(score) || score < BLOCK_THRESHOLD || score > 100) {
        throw new TypeError("Only valid domains scoring at least 70 can be blocklisted.");
      }
      const entries = readEntries();
      const existing = entries.find((entry) => entry.domain === normalized);
      if (existing) {
        existing.lastSeenAt = new Date().toISOString();
        existing.score = Math.max(existing.score, score);
        existing.reason = reason;
      } else {
        entries.push({
          domain: normalized,
          score,
          reason,
          addedAt: new Date().toISOString(),
          lastSeenAt: new Date().toISOString(),
        });
      }
      writeEntries(entries);
      return existing || entries.at(-1);
    },
    hostsFile() {
      const lines = [
        "# ClearSignal local blocklist export.",
        "# Review before use. This file is NOT installed automatically.",
        ...readEntries().flatMap((entry) => [
          `0.0.0.0 ${entry.domain}`,
          `:: ${entry.domain}`,
        ]),
      ];
      return `${lines.join("\n")}\n`;
    },
  };
}

module.exports = { createBlocklist, BLOCK_THRESHOLD, DEFAULT_FILE, isValidDomain };
