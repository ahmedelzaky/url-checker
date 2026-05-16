export type Severity = "low" | "medium" | "high";

export interface Issue {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  points: number; // points deducted
}

export interface CheckResult {
  score: number; // 0-100, higher = safer
  rating: "Safe" | "Likely Safe" | "Suspicious" | "Dangerous";
  issues: Issue[];
  passed: { id: string; title: string }[];
  parsed: {
    protocol: string;
    hostname: string;
    pathname: string;
    full: string;
  } | null;
}

const SUSPICIOUS_TLDS = [
  "zip",
  "mov",
  "xyz",
  "top",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "click",
  "country",
  "kim",
  "work",
  "support",
];
const SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "goo.gl",
  "t.co",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "adf.ly",
  "shorte.st",
  "cutt.ly",
];
const SUSPICIOUS_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "bank",
  "paypal",
  "wallet",
  "confirm",
  "signin",
  "password",
  "billing",
];
const BRAND_NAMES = [
  "paypal",
  "apple",
  "google",
  "microsoft",
  "amazon",
  "facebook",
  "instagram",
  "netflix",
  "bank",
];

function isIPAddress(host: string): boolean {
  return (
    /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ||
    (/^\[?[0-9a-fA-F:]+\]?$/.test(host) && host.includes(":"))
  );
}

// Map common digit/letter substitutions back to their likely original character.
const LOOKALIKE_MAP: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "$": "s",
  "@": "a",
};

function normalizeLookalikes(s: string): string {
  return s.replace(/[013457$@]/g, (c) => LOOKALIKE_MAP[c] ?? c);
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => i);
  for (let j = 1; j <= b.length; j++) {
    let prev = dp[0];
    dp[0] = j;
    for (let i = 1; i <= a.length; i++) {
      const tmp = dp[i];
      dp[i] = a[i - 1] === b[j - 1] ? prev : Math.min(prev, dp[i], dp[i - 1]) + 1;
      prev = tmp;
    }
  }
  return dp[a.length];
}

/**
 * Detect typosquatting / lookalike brand domains.
 * Returns the impersonated brand if the registrable domain looks like a brand
 * but isn't actually that brand (e.g. amazon1, paypa1, g00gle, arnazon).
 */
function detectLookalikeBrand(registrableDomain: string): string | null {
  const sld = registrableDomain.split(".")[0]?.toLowerCase() ?? "";
  if (!sld || sld.length < 4) return null;

  for (const brand of BRAND_NAMES) {
    if (sld === brand) return null; // exact match — legitimate
    const normalized = normalizeLookalikes(sld);
    if (normalized === brand) return brand;
    // Brand with extra chars appended/prepended (amazon1, paypal-secure, myamazon)
    if (sld.includes(brand) && sld !== brand) return brand;

    // Compute distances and allow a slightly more tolerant threshold for long brand names.
    const dist = levenshtein(sld, brand);
    const normDist = levenshtein(normalized, brand);
    const maxEdits = brand.length >= 7 ? 2 : 1; // allow up to 2 edits for long brands

    if (dist <= maxEdits && Math.abs(sld.length - brand.length) <= maxEdits) return brand;
    if (normDist <= maxEdits && Math.abs(normalized.length - brand.length) <= maxEdits) return brand;
  }
  return null;
}

export function checkUrl(input: string): CheckResult {
  const issues: Issue[] = [];
  const passed: { id: string; title: string }[] = [];
  const trimmed = input.trim();

  if (!trimmed) {
    return {
      score: 0,
      rating: "Dangerous",
      issues: [
        {
          id: "empty",
          title: "Empty URL",
          description: "Please enter a URL to check.",
          severity: "high",
          points: 100,
        },
      ],
      passed: [],
      parsed: null,
    };
  }

  let url: URL;
  try {
    const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
    url = new URL(withProto);
    if (!url.hostname || !url.hostname.includes(".")) throw new Error("Invalid hostname");
  } catch {
    return {
      score: 0,
      rating: "Dangerous",
      issues: [
        {
          id: "invalid",
          title: "Invalid URL format",
          description: "The text you entered isn't a valid URL.",
          severity: "high",
          points: 100,
        },
      ],
      passed: [],
      parsed: null,
    };
  }

  const host = url.hostname.toLowerCase();
  const path = url.pathname + url.search;
  const full = url.href;

  // 1. HTTPS
  if (url.protocol !== "https:") {
    issues.push({
      id: "no-https",
      title: "Not using HTTPS",
      description:
        "The site uses an unencrypted HTTP connection. Data sent here can be intercepted.",
      severity: "high",
      points: 25,
    });
  } else {
    passed.push({ id: "https", title: "Uses secure HTTPS connection" });
  }

  // 2. IP address as host
  if (isIPAddress(host)) {
    issues.push({
      id: "ip-host",
      title: "IP address used instead of domain",
      description: "Legitimate sites almost always use a domain name, not a raw IP address.",
      severity: "high",
      points: 25,
    });
  }

  // 3. Excessive hyphens
  const hyphenCount = (host.match(/-/g) || []).length;
  if (hyphenCount >= 4) {
    issues.push({
      id: "many-hyphens",
      title: `Too many hyphens (${hyphenCount})`,
      description: "Phishing domains often pack many hyphens to mimic real brands.",
      severity: "high",
      points: 15,
    });
  } else if (hyphenCount >= 2) {
    issues.push({
      id: "some-hyphens",
      title: `Several hyphens in domain (${hyphenCount})`,
      description: "Multiple hyphens can be a sign of a fake or generated domain.",
      severity: "medium",
      points: 8,
    });
  } else {
    passed.push({ id: "hyphens-ok", title: "Reasonable hyphen count" });
  }

  // 4. Excessive dots / subdomains
  const dotCount = (host.match(/\./g) || []).length;
  if (dotCount >= 5) {
    issues.push({
      id: "many-dots",
      title: `Excessive subdomains (${dotCount} dots)`,
      description:
        "Long chains of subdomains are a classic phishing trick (e.g. paypal.com.login.example.ru).",
      severity: "high",
      points: 15,
    });
  } else if (dotCount >= 4) {
    issues.push({
      id: "some-dots",
      title: `Many subdomains (${dotCount} dots)`,
      description: "Several subdomain levels can be used to disguise the real domain.",
      severity: "medium",
      points: 8,
    });
  } else {
    passed.push({ id: "dots-ok", title: "Normal subdomain depth" });
  }

  // 5. Long URL
  if (full.length > 100) {
    issues.push({
      id: "long-url",
      title: `Very long URL (${full.length} chars)`,
      description: "Unusually long URLs can hide the real destination.",
      severity: "medium",
      points: 8,
    });
  } else {
    passed.push({ id: "length-ok", title: "Reasonable URL length" });
  }

  // 6. Suspicious TLD
  const tld = host.split(".").pop() || "";
  if (SUSPICIOUS_TLDS.includes(tld)) {
    issues.push({
      id: "bad-tld",
      title: `Risky top-level domain (.${tld})`,
      description: "This TLD is heavily abused for spam, phishing, and malware.",
      severity: "high",
      points: 15,
    });
  }

  // 7. URL shortener
  if (SHORTENERS.includes(host)) {
    issues.push({
      id: "shortener",
      title: "URL shortener detected",
      description: "Shorteners hide the actual destination — preview the link before clicking.",
      severity: "medium",
      points: 10,
    });
  }

  // 8. @ symbol in URL (used to obfuscate real host)
  if (full.includes("@")) {
    issues.push({
      id: "at-symbol",
      title: "Contains '@' character",
      description: "The '@' in URLs can be used to hide the real destination host.",
      severity: "high",
      points: 20,
    });
  }

  // 9. Punycode / IDN
  if (host.includes("xn--")) {
    issues.push({
      id: "punycode",
      title: "Punycode (IDN) domain",
      description: "Internationalized domains can imitate real brands using lookalike characters.",
      severity: "high",
      points: 15,
    });
  }

  // 10. Suspicious keywords in path/host
  const haystack = (host + path).toLowerCase();
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter((k) => haystack.includes(k));
  if (foundKeywords.length >= 2) {
    issues.push({
      id: "keywords",
      title: `Phishing keywords: ${foundKeywords.slice(0, 4).join(", ")}`,
      description: "Multiple sensitive words like 'login' or 'verify' are common in phishing URLs.",
      severity: "medium",
      points: 10,
    });
  }

  // 11. Brand impersonation — lookalike registrable domain (amazon1, paypa1, g00gle, arnazon)
  const parts = host.split(".");
  const registrable = parts.slice(-2).join(".");
  const lookalikeBrand = detectLookalikeBrand(registrable);
  if (lookalikeBrand) {
    issues.push({
      id: "lookalike-domain",
      title: `Lookalike domain mimicking "${lookalikeBrand}"`,
      description: `The domain "${registrable}" closely resembles "${lookalikeBrand}" — a classic typosquatting / phishing tactic (e.g. swapping letters for digits like 0→o or 1→l).`,
      severity: "high",
      points: 60,
    });
  } else {
    // 11b. Brand name only in subdomain (e.g. paypal.evil.com)
    const brandInSub = BRAND_NAMES.find((b) => host.includes(b) && !registrable.startsWith(b));
    if (brandInSub) {
      issues.push({
        id: "brand-impersonation",
        title: `Possible "${brandInSub}" impersonation`,
        description: `"${brandInSub}" appears in a subdomain but isn't the real domain — a frequent phishing tactic.`,
        severity: "high",
        points: 40,
      });
    }
  }

  // 12. Numbers mixed in domain
  const digitCount = (host.match(/\d/g) || []).length;
  if (digitCount >= 5) {
    issues.push({
      id: "many-digits",
      title: `Many digits in domain (${digitCount})`,
      description: "Lots of numbers in a hostname can indicate an auto-generated malicious domain.",
      severity: "low",
      points: 5,
    });
  }

  // 13. Non-standard port
  if (url.port && !["80", "443", ""].includes(url.port)) {
    issues.push({
      id: "weird-port",
      title: `Unusual port (${url.port})`,
      description: "Most legitimate sites use the default ports 80 or 443.",
      severity: "medium",
      points: 8,
    });
  }

  const totalDeduction = issues.reduce((sum, i) => sum + i.points, 0);
  const score = Math.max(0, Math.min(100, 100 - totalDeduction));

  let rating: CheckResult["rating"];
  if (score >= 85) rating = "Safe";
  else if (score >= 65) rating = "Likely Safe";
  else if (score >= 35) rating = "Suspicious";
  else rating = "Dangerous";

  return {
    score,
    rating,
    issues: issues.sort((a, b) => b.points - a.points),
    passed,
    parsed: {
      protocol: url.protocol.replace(":", ""),
      hostname: host,
      pathname: url.pathname || "/",
      full,
    },
  };
}
