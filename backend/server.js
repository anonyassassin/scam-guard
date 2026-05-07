import express from "express";
import axios from "axios";
import whois from "whois-json";
import { URL } from "url";
import Database from "better-sqlite3";
import cors from "cors"

const app = express();
app.use(express.json());
app.use(cors())

const db = new Database("scamGuard.db");

db.exec(
  `
    CREATE TABLE IF NOT EXISTS stats (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    scams_blocked INTEGER DEFAULT 0,
    emails_flagged INTEGER DEFAULT 0,
    risky_sites_visited INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS blocked_sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    score INTEGER,
    url TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  `,
);

db.prepare(
  `
  INSERT OR IGNORE INTO stats (id)
  VALUES (1)
`,
).run();

app.get('/stats', (req, res) => {
  const stats = db.prepare(`SELECT * FROM stats WHERE id = 1`).get();
  res.json(stats);
})

app.get('/sites-blocked', (req, res) => {
  try {
    const rows = db
      .prepare("SELECT * FROM blocked_sites ORDER BY timestamp DESC")
      .all();

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "DB error" });
  }
})

app.post("/detect", async (req, res) => {
  const { url } = req.body;
  
  let score = 0;
  let reasons = [];

  try {
    const u = new URL(url);
    const hostname = u.hostname.toLowerCase();


    if (hostname == "www.business-standard.com" || hostname == "www.bbc.com") {
      let verdict = "safe";
      return res.json({ 
      verdict, 
      score, 
      reasons,
      domain: hostname,
      timestamp: new Date().toISOString()
    });
    }




    const path = u.pathname.toLowerCase();
    const fullUrl = url.toLowerCase();
    
    // Trusted domains and platforms
    const trustedDomains = [
      "google.com", "microsoft.com", "paypal.com", "instagram.com", 
      "github.com", "facebook.com", "apple.com", "amazon.com", 
      "twitter.com", "linkedin.com", "allegro.pl", "trezor.io"
    ];
    
    // Legitimate hosting platforms (need content analysis)
    const legitimatePlatforms = [
      "github.io", "gitlab.io", "netlify.app", "vercel.app", 
      "herokuapp.com", "cloudflare.com", "twil.io", "youware.app"
    ];
    
    const isTrustedDomain = trustedDomains.some(domain => 
      hostname === domain || hostname.endsWith(`.${domain}`)
    );
    
    if (isTrustedDomain) {
      return res.json({ verdict: "safe", score: 0, reasons: ["Verified trusted domain"] });
    }

    const isLegitPlatform = legitimatePlatforms.some(platform => hostname.endsWith(platform));

    // 1. CRYPTO WALLET IMPERSONATION (HIGH PRIORITY)
    const cryptoWallets = {
      trezor: ["trezor.io"],
      ledger: ["ledger.com"],
      metamask: ["metamask.io"],
      coinbase: ["coinbase.com"],
      binance: ["binance.com"],
      kraken: ["kraken.com"],
      exodus: ["exodus.com"]
    };

    for (const [wallet, legitimateDomains] of Object.entries(cryptoWallets)) {
      const isLegit = legitimateDomains.some(d => hostname === d || hostname.endsWith(`.${d}`));
      
      if (!isLegit && hostname.includes(wallet)) {
        score += 80;
        reasons.push(`CRITICAL: ${wallet} wallet impersonation`);
        break;
      }
    }

    // Domain hyphens replacing dots (en-trezor-io-start)
    if (/-io-|-com-|-org-|-net-/.test(hostname)) {
      score += 50;
      reasons.push("Domain using hyphens to mimic dots (common phishing trick)");
    }

    // 2. SUBDOMAIN ON HOSTING PLATFORMS
    if (isLegitPlatform) {
      const subdomain = hostname.split('.')[0];
      
      // Random/gibberish subdomain
      if (subdomain.length > 15 || /^[a-z]{10,}$|^[a-z0-9]{20,}/.test(subdomain)) {
        score += 40;
        reasons.push("Suspicious subdomain on hosting platform");
      }
      
      // Brand name in subdomain
      const brands = ["trezor", "ledger", "metamask", "paypal", "amazon", "apple", "microsoft", "google"];
      if (brands.some(brand => subdomain.includes(brand))) {
        score += 60;
        reasons.push("Brand impersonation on hosting platform");
      }
    }

    // 3. NUMBERS + BRAND PATTERN (983283-apple.com)
    const numberBrandPattern = /^\d{4,}[-_]?(apple|google|microsoft|amazon|paypal|facebook)/i;
    if (numberBrandPattern.test(hostname)) {
      score += 75;
      reasons.push("Numbers prefixed to brand name");
    }

    // 4. FAKE JOB RECRUITMENT SCAMS
    const jobScamPatterns = [
      { pattern: /hiring|recruitment|career|jobs?[-_]?portal/i, points: 45, msg: "Fake job recruitment site" },
      { pattern: /(toyota|amazon|google|apple|microsoft|tesla).*hiring/i, points: 55, msg: "Impersonating company recruitment" }
    ];

    for (const { pattern, points, msg } of jobScamPatterns) {
      if (pattern.test(hostname)) {
        score += points;
        reasons.push(msg);
        break;
      }
    }

    // 5. POINTS/MILES/REWARDS SCAMS
    const rewardsPatterns = [
      { pattern: /milhas?[-_]?pontos?|pontos?[-_]?milhas?/i, points: 50, msg: "Fake miles/points redemption" },
      { pattern: /reward|prize|gift[-_]?card|bonus[-_]?point/i, points: 40, msg: "Reward scam keywords" }
    ];

    for (const { pattern, points, msg } of rewardsPatterns) {
      if (pattern.test(hostname)) {
        score += points;
        reasons.push(msg);
        break;
      }
    }

    // 6. SUSPICIOUS TLDs
    const suspiciousTLDs = [
      { pattern: /\.(top|xyz|icu|club|online|site|website|space|buzz|work)$/i, points: 40, msg: "High-risk TLD" },
      { pattern: /\.(shop|store)$/i, points: 30, msg: "E-commerce TLD (often abused)" },
      { pattern: /\.(tk|ml|ga|cf|gq|pw|cc)$/i, points: 50, msg: "Free/disposable TLD" }
    ];

    for (const { pattern, points, msg } of suspiciousTLDs) {
      if (pattern.test(hostname)) {
        score += points;
        reasons.push(msg);
        break;
      }
    }

    // 7. BRAND + GIBBERISH COMBINATIONS
    const majorBrands = {
      allegro: ["allegro.pl"], amazon: ["amazon.com"], paypal: ["paypal.com"],
      ebay: ["ebay.com"], dhl: ["dhl.com"], fedex: ["fedex.com"],
      ups: ["ups.com"], usps: ["usps.com"], netflix: ["netflix.com"],
      spotify: ["spotify.com"], facebook: ["facebook.com"], instagram: ["instagram.com"],
      whatsapp: ["whatsapp.com"], microsoft: ["microsoft.com"], google: ["google.com"],
      apple: ["apple.com"], toyota: ["toyota.com"], tesla: ["tesla.com"],
      trezor: ["trezor.io"], ledger: ["ledger.com"], coinbase: ["coinbase.com"]
    };

    for (const [brand, legitimateDomains] of Object.entries(majorBrands)) {
      const isLegit = legitimateDomains.some(d => hostname === d || hostname.endsWith(`.${d}`));
      
      if (!isLegit && hostname.includes(brand)) {
        const brandIndex = hostname.indexOf(brand);
        const afterBrand = hostname.substring(brandIndex + brand.length).split('.')[0];
        
        if (afterBrand.length > 0) {
          score += 65;
          reasons.push(`${brand} brand with suspicious text`);
        } else {
          score += 50;
          reasons.push(`Possible ${brand} impersonation`);
        }
        break;
      }
    }

    // 8. OFFICIAL/URGENT LANGUAGE
    const urgentWords = [
      "confirm", "conformation", "verification", "verify", "validate",
      "secure", "security", "official", "portal", "central",
      "account", "service", "support", "update", "alert"
    ];
    
    if (urgentWords.some(word => hostname.includes(word))) {
      score += 30;
      reasons.push("Urgent/official keywords in domain");
    }

    // 9. RANDOM NUMBERS IN DOMAIN
    const numberMatches = hostname.match(/\d+/g);
    if (numberMatches) {
      const totalDigits = numberMatches.join('').length;
      if (totalDigits >= 6) {
        score += 35;
        reasons.push(`High number count in domain (${totalDigits} digits)`);
      } else if (totalDigits >= 4) {
        score += 25;
        reasons.push(`Suspicious numbers in domain`);
      }
    }

    // 10. LOGISTICS/DELIVERY/WAREHOUSE SCAMS
    const logisticsPatterns = [
      { pattern: /distrib|logist|armazem|warehouse|courier|parcel|package|delivery|shipping|cargo|entrega/i, points: 45, msg: "Fake logistics service" },
      { pattern: /(dhl|fedex|ups|usps|tnt|dpd|correios)[^.]*(?!\.com)/i, points: 55, msg: "Shipping company impersonation" }
    ];

    for (const { pattern, points, msg } of logisticsPatterns) {
      if (pattern.test(hostname)) {
        score += points;
        reasons.push(msg);
        break;
      }
    }

    // 11. INSURANCE/FINANCIAL SERVICES
    const financialPatterns = [
      { pattern: /seguro|insurance|asesores|advisor|financ|invest|loan|credit/i, points: 40, msg: "Fake financial service" },
      { pattern: /eletric|electric|energia|energy|utilities/i, points: 35, msg: "Fake utility company" }
    ];

    for (const { pattern, points, msg } of financialPatterns) {
      if (pattern.test(hostname) && !isTrustedDomain) {
        score += points;
        reasons.push(msg);
        break;
      }
    }

    // 12. COUNTRY CODE IN DOMAIN
    if (/[-_](fr|de|uk|us|pl|es|it|nl|be|eu|br|pt|cn|ru)\b/i.test(hostname)) {
      score += 15;
      reasons.push("Country code in domain");
    }

    // 13. EXCESSIVE HYPHENS
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      score += 30;
      reasons.push(`Excessive hyphens (${hyphenCount})`);
    } else if (hyphenCount >= 2) {
      score += 20;
      reasons.push("Multiple hyphens in domain");
    }

    // 14. SUBDOMAIN ANALYSIS
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount >= 3 && !isLegitPlatform) {
      score += 40;
      reasons.push(`Excessive subdomains (${subdomainCount} levels)`);
    }
    
    const subdomains = hostname.split('.').slice(0, -2);
    const hasRandomSubdomain = subdomains.some(sub => {
      return sub.length <= 2 || (/^[a-z0-9]{8,}$/i.test(sub) && !/^(www|mail|api|cdn|app|web|shop|central)$/.test(sub));
    });
    
    if (hasRandomSubdomain && subdomainCount >= 1) {
      score += 30;
      reasons.push("Random subdomain pattern");
    }

    // 15. TRACKING/REDIRECT DOMAINS
    const trackingPatterns = [
      { pattern: /send(ibm|grid|pulse|in|mail)/i, points: 50, msg: "Email tracking domain" },
      { pattern: /click|track|link|redirect|goto|redir/i, points: 45, msg: "URL redirect service" },
      { pattern: /(bit|tinyurl|shorturl)\.ly|goo\.gl|ow\.ly/i, points: 45, msg: "URL shortener" }
    ];

    for (const { pattern, points, msg } of trackingPatterns) {
      if (pattern.test(hostname)) {
        score += points;
        reasons.push(msg);
        break;
      }
    }

    // 16. SUSPICIOUS PATH PATTERNS
    if (path.length > 50) {
      score += 20;
      reasons.push("Long URL path");
    }

    // Landing page patterns (lp-, /lp)
    if (/\/lp[-_]?\d+|\/landing/.test(fullUrl)) {
      score += 25;
      reasons.push("Generic landing page pattern");
    }

    if (fullUrl.includes('/mk/cl/') || fullUrl.includes('/click/') || fullUrl.includes('/track/')) {
      score += 30;
      reasons.push("Tracking redirect path");
    }

    // 17. DOMAIN AGE CHECK
    try {
      const baseDomain = hostname.split('.').slice(-2).join('.');
      const whoisData = await whois(baseDomain);
      if (whoisData.creationDate) {
        const ageInDays = (Date.now() - new Date(whoisData.creationDate)) / 86400000;
        if (ageInDays < 7) {
          score += 50;
          reasons.push(`Domain ${Math.floor(ageInDays)} days old`);
        } else if (ageInDays < 30) {
          score += 35;
          reasons.push("Recently registered domain");
        } else if (ageInDays < 90) {
          score += 20;
          reasons.push("Domain less than 3 months old");
        }
      }
    } catch (e) {
      // WHOIS failed - common for subdomains on platforms
      if (!isLegitPlatform) {
        score += 10;
      }
    }

    // 18. TYPOSQUATTING
    const brandVariants = {
      google: ["g00gle", "gooogle", "googl3", "gogle"],
      microsoft: ["micros0ft", "microsft", "rnicrosof"],
      paypal: ["paypai", "paypa1", "paypaal"],
      instagram: ["instagrarn", "instagran", "1nstagram"],
      trezor: ["trezar", "trezer", "trez0r", "trexor"],
      ledger: ["ledgar", "1edger", "ledgr"],
      apple: ["app1e", "appl3", "aple", "appie"],
      amazon: ["amaz0n", "arnazon", "amazom"]
    };

    for (const [brand, variants] of Object.entries(brandVariants)) {
      if (variants.some(v => hostname.includes(v))) {
        score += 70;
        reasons.push(`Typosquatting: ${brand}`);
        break;
      }
    }

    // 19. FETCH PAGE CONTENT
    let html = "";
    try {
      const response = await axios.get(url, { 
        timeout: 5000,
        maxRedirects: 5,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        validateStatus: (status) => status < 500
      });
      html = response.data.toLowerCase();
      
      // Redirect detection
      if (response.request?.res?.responseUrl) {
        const finalUrl = new URL(response.request.res.responseUrl);
        if (finalUrl.hostname !== hostname) {
          score += 30;
          reasons.push(`Redirects to: ${finalUrl.hostname}`);
        }
      }
      
      // Phishing language
      const phishingPhrases = [
        { phrase: /verify (your|account|identity|wallet)/gi, points: 40 },
        { phrase: /suspended|locked|limited|restricted|blocked/gi, points: 35 },
        { phrase: /(claim|redeem).*(prize|reward|gift|points|miles)/gi, points: 45 },
        { phrase: /update.*(payment|billing|card|wallet)/gi, points: 40 },
        { phrase: /confirm.*(identity|account|information)/gi, points: 35 },
        { phrase: /(urgent|immediate|act now|limited time)/gi, points: 30 },
        { phrase: /recovery.?phrase|seed.?phrase|private.?key/gi, points: 60 }
      ];

      for (const { phrase, points } of phishingPhrases) {
        if (phrase.test(html)) {
          score += points;
          reasons.push("Phishing language detected");
          break;
        }
      }

      // Crypto-specific warnings
      if (/seed|recovery.*phrase|12.*word|24.*word|private.*key|mnemonic/gi.test(html)) {
        score += 70;
        reasons.push("CRITICAL: Requests crypto recovery phrase");
      }

      // Login/password forms
      const hasLoginForm = /<form[^>]*>/gi.test(html) && /password|passwd|pwd/i.test(html);
      if (hasLoginForm) {
        score += 40;
        reasons.push("Login form on untrusted domain");
      }

      // Payment info
      if (/credit.?card|card.?number|cvv|cvc/gi.test(html)) {
        score += 50;
        reasons.push("Requests payment information");
      }

    } catch (e) {
      if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT') {
        score += 20;
        reasons.push("Connection failed");
      }
    }

    // 20. SSL CHECK
    if (u.protocol === "http:") {
      score += 30;
      reasons.push("No HTTPS encryption");
    }

    // 21. LOGIN/ACCOUNT PAGES
    if ((path.includes("login") || path.includes("signin") || path.includes("account") || path.includes("start")) && !isTrustedDomain) {
      score += 25;
      reasons.push("Login/account page on untrusted domain");
    }

    // 22. ENCODED DATA
    if (/[A-Za-z0-9+\/=]{40,}/.test(fullUrl)) {
      score += 15;
      reasons.push("Encoded data in URL");
    }

    // 23. CALCULATE VERDICT
    let verdict = "safe";
    
    if (score >= 80) {
      verdict = "scam";
      
      try {
        db.prepare(`UPDATE stats SET scams_blocked = scams_blocked + 1 WHERE id = 1`).run();
        db.prepare(`INSERT INTO blocked_sites (domain, url, score, timestamp) VALUES (?, ?, ?, datetime('now'))`).run(hostname, url, score);
      } catch (dbErr) {
        console.error("Database error:", dbErr);
      }
      
    } else if (score >= 50) {
      verdict = "suspicious";
      try {
      db.prepare(`UPDATE stats SET risky_sites_visited = risky_sites_visited + 1 WHERE id = 1`).run();

      } catch(dbError) {
        console.log("Database error: ", dbError);
      }
    } else if (score >= 25) {
      verdict = "caution";
    }

    res.json({ 
      verdict, 
      score, 
      reasons,
      domain: hostname,
      timestamp: new Date().toISOString()
    });

  } catch (e) {
    console.error("Detection error:", e);
    res.status(400).json({ 
      verdict: "error", 
      score: 0, 
      reasons: [e.message.includes("Invalid URL") ? "Malformed URL" : "Analysis failed"],
      error: e.message
    });
  }
});





// app.post("/detect", async (req, res) => {
//   const { url } = req.body;
//   let score = 0;
//   let reasons = [];

//   try {
//     const u = new URL(url);
//     console.log(u)
//     const hostname = u.hostname;

//     // Domain age (ONLY base domain)
//     try {
//       const whoisData = await whois(u.hostname);
//       if (whoisData.creationDate) {
//         const age = (Date.now() - new Date(whoisData.creationDate)) / 86400000;
//         if (age < 30) {
//           score += 40;
//           reasons.push("Domain registered recently");
//         }
//       }
//     } catch (e){
//       console.log(e);
//       reasons.push("WHOIS lookup failed (common for hosted platforms)");
//     }

//     // Brand impersonation
//     if (hostname.includes("gift") || hostname.includes("reward")) {
//       score += 20;
//       reasons.push("Gift/reward lure detected");
//     }

//     // Page content
//     try {
//       const r = await axios.get(url, { timeout: 4000 });
//       const html = r.data.toLowerCase();

//       if (
//         html.includes("claim") ||
//         html.includes("limited time") ||
//         html.includes("verify") ||
//         html.includes("free")
//       ) {
//         score += 25;
//         reasons.push("Phishing language detected");
//       }

//       const brands = ["google", "microsoft", "paypal", "instagram", "github"];

//       for (const brand of brands) {
//         if (hostname.endsWith(`${brand}.com`)) {
//           console.log("yes");
//           score = 0;
//           verdict = "safe";
//           res.json({ verdict, score, reasons });
//           return;
//         }
//         if (html.includes(brand) && !hostname.endsWith(`${brand}.com`)) {
//           score += 50;
//           reasons.push(`Impersonating ${brand}`);
//         }
//       }
//     } catch {
//       score += 10;
//       reasons.push("Failed to fetch page content");
//     }

//     // Verdict logic
//     let verdict = "safe";
//     if (score >= 70) {
//       db.prepare(
//         `
//   UPDATE stats
//   SET scams_blocked = scams_blocked + 1
//   WHERE id = 1
// `,
//       ).run();

//       db.prepare(
//         `
//   INSERT INTO blocked_sites (domain, url)
//   VALUES (?, ?)
// `,
//       ).run(u.origin, url);

//       verdict = "scam"
//     } else if (score >= 40) verdict = "suspicious";

//     res.json({ verdict, score, reasons });
//   } catch (e){
//     console.log(e);
//     res.json({ verdict: "invalid_url", score: 0, reasons: ["Malformed URL"] });
//   }
// });

app.listen(8000, () =>
  console.log("Scam detection engine running on https://localhost:8000"),
);
