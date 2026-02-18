#!/usr/bin/env node

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function expandHome(inputPath) {
  if (!inputPath) {
    return inputPath;
  }
  if (inputPath === "~") {
    return os.homedir();
  }
  if (inputPath.startsWith("~/")) {
    return path.join(os.homedir(), inputPath.slice(2));
  }
  return inputPath;
}

function parseZulipRc(filePath, profile = "api") {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const sections = {};
    let currentSection = "api";
    sections[currentSection] = {};

    for (const rawLine of raw.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) {
        continue;
      }

      const sectionMatch = line.match(/^\[(.+)\]$/);
      if (sectionMatch) {
        currentSection = sectionMatch[1].trim();
        if (!sections[currentSection]) {
          sections[currentSection] = {};
        }
        continue;
      }

      const pair = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);
      if (!pair) {
        continue;
      }

      sections[currentSection][pair[1]] = pair[2];
    }

    let selected = sections[profile];
    if (!selected) {
      selected = Object.values(sections).find((s) => s.email && s.key && s.site);
    }

    return {
      loaded: !!selected,
      site: selected?.site || "",
      email: selected?.email || "",
      key: selected?.key || "",
      filePath,
      profile,
    };
  } catch {
    return {
      loaded: false,
      site: "",
      email: "",
      key: "",
      filePath,
      profile,
    };
  }
}

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const message = args.filter((arg) => arg !== "--dry-run").join(" ").trim();

const zulipRcPath = expandHome(process.env.ZULIPRC_PATH || "~/.zuliprc");
const zulipRcProfile = process.env.ZULIP_PROFILE || "api";
const parsedRc = parseZulipRc(zulipRcPath, zulipRcProfile);

const site = (process.env.ZULIP_SITE || parsedRc.site || "").replace(/\/+$/, "");
const botEmail = process.env.ZULIP_BOT_EMAIL || parsedRc.email || "";
const botApiKey = process.env.ZULIP_BOT_API_KEY || parsedRc.key || "";
const messageTypeRaw = String(process.env.ZULIP_MESSAGE_TYPE || "stream")
  .trim()
  .toLowerCase();
const messageType = messageTypeRaw === "private" ? "private" : "stream";
const recipient = process.env.ZULIP_TO || "8-Tessa";
const streamName = String(process.env.ZULIP_STREAM || "coding").trim();
const topic = String(process.env.ZULIP_TOPIC || "verified-cad").trim();

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

if (!site) {
  fail("Missing ZULIP_SITE");
}
if (!botEmail) {
  fail("Missing ZULIP_BOT_EMAIL");
}
if (!botApiKey) {
  fail("Missing ZULIP_BOT_API_KEY");
}
if (!dryRun && !message) {
  fail("Usage: node looper/send-zulip-dm.js \"your message\"");
}
if (messageType === "stream") {
  if (!streamName) {
    fail("Missing ZULIP_STREAM for stream messages");
  }
  if (!topic) {
    fail("Missing ZULIP_TOPIC for stream messages");
  }
}
if (typeof fetch !== "function") {
  fail("This Node runtime does not expose global fetch");
}

if (dryRun) {
  const source = parsedRc.loaded ? `zuliprc:${parsedRc.filePath} [${parsedRc.profile}]` : "env-only";
  const target =
    messageType === "private" ? `to=${recipient}` : `stream=${streamName} topic=${topic}`;
  console.log(
    `DRY_RUN_OK source=${source} site=${site ? "set" : "missing"} email=${botEmail ? "set" : "missing"} key=${botApiKey ? "set" : "missing"} type=${messageType} ${target}`,
  );
  process.exit(0);
}

const params = new URLSearchParams();
params.set("type", messageType);
params.set("content", message);

const auth = Buffer.from(`${botEmail}:${botApiKey}`).toString("base64");
const authHeader = `Basic ${auth}`;

function looksLikeEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isIntegerString(value) {
  return /^\d+$/.test(value);
}

function norm(value) {
  return String(value || "").trim().toLowerCase();
}

async function resolveRecipient(rawRecipient) {
  const trimmed = String(rawRecipient || "").trim();
  if (!trimmed) {
    fail("Recipient is empty");
  }

  if (looksLikeEmail(trimmed)) {
    return trimmed;
  }

  if (isIntegerString(trimmed)) {
    return Number(trimmed);
  }

  const res = await fetch(`${site}/api/v1/users`, {
    method: "GET",
    headers: { Authorization: authHeader },
  });

  if (!res.ok) {
    const body = await res.text();
    fail(`Could not resolve recipient '${trimmed}' (users lookup failed ${res.status}: ${body.slice(0, 220)})`);
  }

  const data = await res.json();
  const members = Array.isArray(data.members) ? data.members : [];
  const target = norm(trimmed.replace(/^@/, ""));

  const directMatch = members.find((m) => {
    const names = [
      m.full_name,
      m.email,
      m.delivery_email,
      m.short_name,
      m.name,
      m.user_id != null ? String(m.user_id) : "",
    ];
    return names.some((candidate) => norm(candidate) === target);
  });

  if (directMatch) {
    return directMatch.user_id ?? directMatch.delivery_email ?? directMatch.email;
  }

  const fuzzyMatch = members.find((m) => norm(m.full_name).includes(target) || target.includes(norm(m.full_name)));
  if (fuzzyMatch) {
    return fuzzyMatch.user_id ?? fuzzyMatch.delivery_email ?? fuzzyMatch.email;
  }

  fail(`Could not resolve recipient '${trimmed}' in Zulip users list`);
}

async function main() {
  try {
    if (messageType === "private") {
      const resolvedRecipient = await resolveRecipient(recipient);
      params.set("to", JSON.stringify([resolvedRecipient]));
    } else {
      params.set("to", streamName);
      params.set("topic", topic);
    }

    const res = await fetch(`${site}/api/v1/messages`, {
      method: "POST",
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });

    if (!res.ok) {
      const text = await res.text();
      fail(`Zulip request failed (${res.status}): ${text.slice(0, 300)}`);
    }

    const data = await res.json();
    if (messageType === "private") {
      console.log(`OK message_id=${data.id ?? "unknown"} type=private to=${recipient}`);
    } else {
      console.log(`OK message_id=${data.id ?? "unknown"} type=stream stream=${streamName} topic=${topic}`);
    }
  } catch (error) {
    fail(`Failed to send Zulip message: ${error?.message || String(error)}`);
  }
}

main();
