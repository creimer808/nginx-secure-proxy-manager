#!/usr/bin/env node

// This file does a few things to ensure that the Locales are present and valid:
// - Ensures that the name of the locale exists in the language list
// - Ensures that each locale contains the translations used in the application
// - Ensures that there are no unused translations in the locale files
// - Also checks the error messages returned by the backend

const allLocales = [
  ["en", "en-US"],
  ["de", "de-DE"],
  ["pt", "pt-PT"],
  ["es", "es-ES"],
  ["et", "et-EE"],
  ["fr", "fr-FR"],
  ["ga", "ga-IE"],
  ["it", "it-IT"],
  ["ja", "ja-JP"],
  ["nl", "nl-NL"],
  ["pl", "pl-PL"],
  ["ru", "ru-RU"],
  ["sk", "sk-SK"],
  ["cs", "cs-CZ"],
  ["vi", "vi-VN"],
  ["zh", "zh-CN"],
  ["ko", "ko-KR"],
  ["bg", "bg-BG"],
  ["id", "id-ID"],
  ["tr", "tr-TR"],
  ["hu", "hu-HU"],
  ["no", "no-NO"],
];

const ignoreUnused = [/^.*$/];

const fs = require("fs");
const path = require("path");

// Parse backend errors
const BACKEND_ERRORS_FILE = "../backend/internal/errors/errors.go";
const BACKEND_ERRORS = [];
/*
try {
	const backendErrorsContent = fs.readFileSync(BACKEND_ERRORS_FILE, "utf8");
	const backendErrorsContentRes = [
		...backendErrorsContent.matchAll(/(?:errors|eris)\.New\("([^"]+)"\)/g),
	];
	backendErrorsContentRes.map((item) => {
		BACKEND_ERRORS.push("error." + item[1]);
		return null;
	});
} catch (err) {
	console.log("\x1b[31m%s\x1b[0m", err);
	process.exit(1);
}
*/

// Collect the message ids the application actually uses.
//
// This used to shell out to a bare `yarn locale-extract`. With no `yarn` on
// PATH the spawn failed silently, the temp file stayed empty, and the script
// died on `require` with "Unexpected end of JSON input" instead of naming the
// missing id — which is how a `<T id="action.save" />` that resolves to no
// message shipped and rendered its own id as button text.
//
// `formatjs extract` cannot be used here either: it aborts and writes `{}` as
// soon as it meets a computed `id={...}`, and this codebase has several. So
// scan the source for literal ids directly. Computed ids are counted and
// reported, but cannot be checked.
const SOURCE_ROOT = "src";
const LITERAL_ID_PATTERNS = [/<T\s[^>]*?\bid="([^"]+)"/gs, /\bid:\s*"([^"]+)"\s*\}/g];
const COMPUTED_ID_PATTERN = /<T\s[^>]*?\bid=\{/gs;

const sourceFiles = (directory) => {
  const found = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...sourceFiles(full));
    else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) found.push(full);
  }
  return found;
};

const allLocalesInProject = {};
let computedIds = 0;
for (const file of sourceFiles(SOURCE_ROOT)) {
  const content = fs.readFileSync(file, "utf8");
  for (const pattern of LITERAL_ID_PATTERNS) {
    for (const match of content.matchAll(pattern)) {
      allLocalesInProject[match[1]] = { file };
    }
  }
  computedIds += [...content.matchAll(COMPUTED_ID_PATTERN)].length;
}
if (!Object.keys(allLocalesInProject).length) {
  console.log("\x1b[31m%s\x1b[0m", `ERROR: found no message ids under ${SOURCE_ROOT}/`);
  process.exit(1);
}

// get list og language names and locales
const langList = require("./src/locale/src/lang-list.json");

// store a list of all validation errors
const allErrors = [];
const allWarnings = [];
const allKeys = [];

const checkLangList = (fullCode) => {
  const key = "locale-" + fullCode;
  if (typeof langList[key] === "undefined") {
    allErrors.push("ERROR: `" + key + "` language does not exist in lang-list.json");
  }
};

const compareLocale = (locale) => {
  const projectLocaleKeys = Object.keys(allLocalesInProject);
  // Check that locale contains the items used in the codebase.
  // `en` is the source of truth: a message id used in code but absent there
  // renders as the raw id in the UI, so it is an error. The other locales are
  // legitimately incomplete and are reported as warnings.
  const severity = locale[0] === "en" ? allErrors : allWarnings;
  const label = locale[0] === "en" ? "ERROR" : "WARN";
  projectLocaleKeys.map((key) => {
    if (typeof locale.data[key] === "undefined") {
      severity.push(label + ": `" + locale[0] + "` does not contain item: `" + key + "`");
    }
    return null;
  });
  // Check that locale contains all error.* items
  BACKEND_ERRORS.forEach((key) => {
    if (typeof locale.data[key] === "undefined") {
      allErrors.push("ERROR: `" + locale[0] + "` does not contain item: `" + key + "`");
    }
    return null;
  });

  // Check that locale does not contain items not used in the codebase
  const localeKeys = Object.keys(locale.data);
  localeKeys.map((key) => {
    let ignored = false;
    ignoreUnused.map((regex) => {
      if (key.match(regex)) {
        ignored = true;
      }
      return null;
    });

    if (!ignored && typeof allLocalesInProject[key] === "undefined") {
      // ensure this key doesn't exist in the backend errors either
      if (!BACKEND_ERRORS.includes(key)) {
        allErrors.push("ERROR: `" + locale[0] + "` contains unused item: `" + key + "`");
      }
    }

    // Add this key to allKeys
    if (allKeys.indexOf(key) === -1) {
      allKeys.push(key);
    }
    return null;
  });
};

// Checks for any keys missing from this locale, that
// have been defined in any other locales
const checkForMissing = (locale) => {
  allKeys.forEach((key) => {
    if (typeof locale.data[key] === "undefined") {
      allWarnings.push("WARN: `" + locale[0] + "` does not contain item: `" + key + "`");
    }
    return null;
  });
};

// Local all locale data
allLocales.map((locale, idx) => {
  checkLangList(locale[1]);
  allLocales[idx].data = require("./src/locale/src/" + locale[0] + ".json");
  return null;
});

// Verify all locale data
allLocales.map((locale) => {
  compareLocale(locale);
  checkForMissing(locale);
  return null;
});

if (allErrors.length) {
  allErrors.map((err) => {
    console.log("\x1b[31m%s\x1b[0m", err);
    return null;
  });
}
if (allWarnings.length) {
  allWarnings.map((err) => {
    console.log("\x1b[33m%s\x1b[0m", err);
    return null;
  });
}

if (allErrors.length) {
  process.exit(1);
}

console.log(
  "\x1b[32m%s\x1b[0m",
  `Locale check passed (${Object.keys(allLocalesInProject).length} literal ids checked, ${computedIds} computed ids not checkable)`,
);
process.exit(0);
