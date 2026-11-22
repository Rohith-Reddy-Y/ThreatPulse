/**
 * ThreatPulse — Threat Landscape analytics.
 *
 * Summarises the caller's OWN articles (same scope as their feed) into the
 * views enterprise CTI platforms lead with:
 *   - MITRE ATT&CK: techniques by tactic. A technique counts as EXPLICIT when the
 *     report cites its ID, INFERRED when the report describes the behaviour
 *     (e.g. "password spraying" -> T1110). The two are always reported separately.
 *   - Threat actors: who appears most, attributed origin, sectors, CVEs, last seen
 *   - Vulnerabilities: most-reported CVEs with exploitation / PoC / patch signals
 *   - Targeting: sectors and countries named in the reports
 *
 * Pure computation over text the user can already see. Nothing is fetched.
 */

const geo = require('./geo');

// Enterprise ATT&CK tactics in kill-chain order
const TACTICS = [
  ['TA0043', 'Reconnaissance'], ['TA0042', 'Resource Development'], ['TA0001', 'Initial Access'],
  ['TA0002', 'Execution'], ['TA0003', 'Persistence'], ['TA0004', 'Privilege Escalation'],
  ['TA0005', 'Defense Evasion'], ['TA0006', 'Credential Access'], ['TA0007', 'Discovery'],
  ['TA0008', 'Lateral Movement'], ['TA0009', 'Collection'], ['TA0011', 'Command and Control'],
  ['TA0010', 'Exfiltration'], ['TA0040', 'Impact'],
];

// Technique catalogue: id -> [name, primary tactic]. Techniques that belong to
// several tactics are listed under the one they are most often reported for.
const TECHNIQUES = {
  T1595: ['Active Scanning', 'TA0043'], T1592: ['Gather Victim Host Information', 'TA0043'],
  T1589: ['Gather Victim Identity Information', 'TA0043'], T1598: ['Phishing for Information', 'TA0043'],
  T1583: ['Acquire Infrastructure', 'TA0042'], T1584: ['Compromise Infrastructure', 'TA0042'],
  T1587: ['Develop Capabilities', 'TA0042'], T1588: ['Obtain Capabilities', 'TA0042'],
  T1608: ['Stage Capabilities', 'TA0042'], T1650: ['Acquire Access', 'TA0042'],
  T1566: ['Phishing', 'TA0001'], T1190: ['Exploit Public-Facing Application', 'TA0001'],
  T1195: ['Supply Chain Compromise', 'TA0001'], T1133: ['External Remote Services', 'TA0001'],
  T1078: ['Valid Accounts', 'TA0001'], T1189: ['Drive-by Compromise', 'TA0001'],
  T1199: ['Trusted Relationship', 'TA0001'], T1091: ['Replication Through Removable Media', 'TA0001'],
  T1059: ['Command and Scripting Interpreter', 'TA0002'], T1204: ['User Execution', 'TA0002'],
  T1203: ['Exploitation for Client Execution', 'TA0002'], T1047: ['Windows Management Instrumentation', 'TA0002'],
  T1053: ['Scheduled Task/Job', 'TA0003'], T1547: ['Boot or Logon Autostart Execution', 'TA0003'],
  T1505: ['Server Software Component', 'TA0003'], T1543: ['Create or Modify System Process', 'TA0003'],
  T1176: ['Browser Extensions', 'TA0003'], T1136: ['Create Account', 'TA0003'],
  T1068: ['Exploitation for Privilege Escalation', 'TA0004'], T1548: ['Abuse Elevation Control Mechanism', 'TA0004'],
  T1562: ['Impair Defenses', 'TA0005'], T1027: ['Obfuscated Files or Information', 'TA0005'],
  T1055: ['Process Injection', 'TA0005'], T1218: ['System Binary Proxy Execution', 'TA0005'],
  T1574: ['Hijack Execution Flow', 'TA0005'], T1036: ['Masquerading', 'TA0005'],
  T1553: ['Subvert Trust Controls', 'TA0005'], T1014: ['Rootkit', 'TA0005'],
  T1070: ['Indicator Removal', 'TA0005'], T1497: ['Virtualization/Sandbox Evasion', 'TA0005'],
  T1003: ['OS Credential Dumping', 'TA0006'], T1110: ['Brute Force', 'TA0006'],
  T1555: ['Credentials from Password Stores', 'TA0006'], T1539: ['Steal Web Session Cookie', 'TA0006'],
  T1557: ['Adversary-in-the-Middle', 'TA0006'], T1621: ['Multi-Factor Authentication Request Generation', 'TA0006'],
  T1056: ['Input Capture', 'TA0006'], T1552: ['Unsecured Credentials', 'TA0006'],
  T1082: ['System Information Discovery', 'TA0007'], T1046: ['Network Service Discovery', 'TA0007'],
  T1087: ['Account Discovery', 'TA0007'], T1083: ['File and Directory Discovery', 'TA0007'],
  T1021: ['Remote Services', 'TA0008'], T1570: ['Lateral Tool Transfer', 'TA0008'],
  T1114: ['Email Collection', 'TA0009'], T1113: ['Screen Capture', 'TA0009'],
  T1005: ['Data from Local System', 'TA0009'], T1560: ['Archive Collected Data', 'TA0009'],
  T1071: ['Application Layer Protocol', 'TA0011'], T1090: ['Proxy', 'TA0011'],
  T1572: ['Protocol Tunneling', 'TA0011'], T1219: ['Remote Access Software', 'TA0011'],
  T1105: ['Ingress Tool Transfer', 'TA0011'], T1102: ['Web Service', 'TA0011'],
  T1041: ['Exfiltration Over C2 Channel', 'TA0010'], T1567: ['Exfiltration Over Web Service', 'TA0010'],
  T1048: ['Exfiltration Over Alternative Protocol', 'TA0010'],
  T1486: ['Data Encrypted for Impact', 'TA0040'], T1490: ['Inhibit System Recovery', 'TA0040'],
  T1485: ['Data Destruction', 'TA0040'], T1498: ['Network Denial of Service', 'TA0040'],
  T1499: ['Endpoint Denial of Service', 'TA0040'], T1491: ['Defacement', 'TA0040'],
  T1496: ['Resource Hijacking', 'TA0040'], T1657: ['Financial Theft', 'TA0040'],
  T1489: ['Service Stop', 'TA0040'], T1565: ['Data Manipulation', 'TA0040'],
};

// Behaviour described in a report -> technique (INFERRED). Deliberately
// conservative: specific phrases only, so the heatmap stays defensible.
const INFER = [
  ['T1595', /\b(mass[- ]scann?(ing|ed)?|scanning (campaign|activity) for|internet-wide scan)/i],
  ['T1583', /\b(bulletproof hosting|botnet infrastructure|registered (look-?alike|typosquat(ted)?) domains?)\b/i],
  ['T1584', /\b(compromised (routers?|edge devices|wordpress sites)|ORB network|operational relay box)/i],
  ['T1588', /\b(exploit kits?|purchased (an )?exploits?|malware-as-a-service)\b/i],
  ['T1650', /\b(initial access brokers?)\b/i],
  ['T1566', /\b(phishing|spear-?phishing|malspam|smishing|vishing|phishing emails?)\b/i],
  ['T1190', /\b(actively exploited|exploited in the wild|exploitation of|zero-day exploitation|mass exploitation)\b[^.]{0,120}\b(vpn|firewall|gateway|appliance|server|edge device|public-facing|citrix|netscaler|fortinet|fortigate|fortios|ivanti|palo alto|pan-os|vcenter|exchange|sharepoint|confluence|moveit|sonicwall|cisco asa|f5 big-ip)\b/i],
  ['T1195', /\b(supply[- ]chain (attack|compromise)|malicious (npm|pypi|nuget|rubygems) packages?|typosquat(ting|ted) packages?|compromised (update|build) (server|pipeline))\b/i],
  ['T1133', /\b(exposed rdp|compromised vpn (accounts?|credentials)|vpn credentials)\b/i],
  ['T1078', /\b(stolen credentials|compromised credentials|valid accounts|credential(s)? (were )?leaked)\b/i],
  ['T1189', /\b(drive-by (download|compromise)|watering[- ]hole|malvertising)\b/i],
  ['T1199', /\b(managed service provider|MSP compromise|third-party (vendor|supplier) (breach|compromise))\b/i],
  ['T1091', /\b(usb worm|infected usb|removable (media|drives?))\b/i],
  ['T1059', /\b(powershell|vbscript|malicious (javascript|python|bash) (script|loader)|cmd\.exe|applescript)\b/i],
  ['T1204', /\b(malicious (attachment|macro|lnk|shortcut)|lure documents?|clickfix|fake captcha|macro-enabled)\b/i],
  ['T1047', /\b(wmi(c)?|windows management instrumentation)\b/i],
  ['T1053', /\b(scheduled tasks?|cron jobs?)\b/i],
  ['T1547', /\b(registry run keys?|autostart|startup folder|launchagent|launch agents?)\b/i],
  ['T1505', /\b(web ?shells?)\b/i],
  ['T1543', /\b(malicious (windows )?service|systemd service|launch daemon)\b/i],
  ['T1176', /\b(malicious (browser|chrome|firefox|edge) extensions?)\b/i],
  ['T1068', /\b(privilege escalation|elevation of privilege|local privilege|LPE)\b/i],
  ['T1562', /\b(disabl(e|es|ed|ing) (antivirus|edr|defender|security (tools|software))|edr killer|edr-killer|byovd|bring your own vulnerable driver)\b/i],
  ['T1027', /\b(obfuscat(ed|ion)|packed (payload|binary)|encrypted payload|steganograph(y|ic))\b/i],
  ['T1055', /\b(process (injection|hollowing)|dll injection|reflective (dll|loading))\b/i],
  ['T1218', /\b(lolbins?|living[- ]off[- ]the[- ]land|rundll32|mshta|regsvr32|msiexec)\b/i],
  ['T1574', /\b(dll side-?loading|dll hijack(ing)?|search order hijack)/i],
  ['T1036', /\b(masquerad(es|ing|ed)|fake (installer|update|browser update)|trojani[sz]ed (installer|app))\b/i],
  ['T1553', /\b(signed (malware|driver)|stolen code[- ]signing|code[- ]signing certificates?)\b/i],
  ['T1014', /\b(rootkit|bootkit)\b/i],
  ['T1070', /\b(clear(ed|s)? (event )?logs|log (deletion|wiping)|indicator removal)\b/i],
  ['T1497', /\b(anti-(vm|sandbox|analysis)|sandbox evasion)\b/i],
  ['T1003', /\b(credential dumping|mimikatz|lsass|ntds\.dit|sam hive)\b/i],
  ['T1110', /\b(brute[- ]forc(e|ing)|password spray(ing)?|credential stuffing)\b/i],
  ['T1555', /\b(info-?stealers?|stealer malware|password stealer|lumma|redline|vidar|stealc|raccoon stealer)\b/i],
  ['T1539', /\b(session (cookie|token)s? (theft|stolen|hijack)|cookie theft|session hijacking)\b/i],
  ['T1557', /\b(adversary-in-the-middle|AiTM|man-in-the-middle|evilginx)\b/i],
  ['T1621', /\b(mfa (fatigue|bombing|push spam)|push bombing)\b/i],
  ['T1056', /\b(keylog(ger|ging)|form-?grabb(er|ing)|skimm(er|ing))\b/i],
  ['T1046', /\b(port scan(ning)?|network (scan|reconnaissance)|internal reconnaissance)\b/i],
  ['T1021', /\b(psexec|remote desktop protocol|rdp lateral|smb lateral|lateral movement via (rdp|smb|ssh))\b/i],
  ['T1114', /\b(email (accounts?|mailboxes) (accessed|compromised)|mailbox access|email exfiltration)\b/i],
  ['T1113', /\b(screen ?shots? capture|screen capture)\b/i],
  ['T1071', /\b(command[- ]and[- ]control|c2 (server|infrastructure|channel)|c&c|cobalt strike|sliver|brute ratel|havoc c2)\b/i],
  ['T1090', /\b(residential proxy|proxy network|proxyware|proxy botnet)\b/i],
  ['T1572', /\b(dns tunnel(l)?ing|ngrok|cloudflare tunnel|ssh tunnel)\b/i],
  ['T1219', /\b(anydesk|screenconnect|connectwise control|teamviewer|rmm tools?|remote monitoring and management)\b/i],
  ['T1105', /\b(dropper|downloader|malware loader|second-stage payload)\b/i],
  ['T1102', /\b(telegram (bot|api) (for|as) c2|discord (webhook|cdn) (abuse|c2)|dead drop resolver)\b/i],
  ['T1567', /\b(exfiltrat(ed|ion|ing)[^.]{0,60}(mega|google drive|dropbox|onedrive|cloud storage|rclone)|rclone)\b/i],
  ['T1041', /\b(data exfiltration|exfiltrat(ed|ing) (data|files|information))\b/i],
  ['T1486', /\b(ransomware (attack|encrypt|infection|payload|strain|variant)|encrypt(ed|s|ing) (files|systems|servers|data))\b/i],
  ['T1490', /\b(shadow copies|vssadmin|delet(e|ed|es|ing) backups)\b/i],
  ['T1485', /\b(wiper( malware)?|data destruction|destructive malware)\b/i],
  ['T1498', /\b(ddos|distributed denial[- ]of[- ]service)\b/i],
  ['T1499', /\b(denial[- ]of[- ]service (vulnerability|flaw|condition)|dos (vulnerability|flaw))\b/i],
  ['T1491', /\b(defac(ed|ement|ing))\b/i],
  ['T1496', /\b(cryptojack(ing)?|crypto-?miner|coin ?miner|xmrig|resource hijacking)\b/i],
  ['T1657', /\b(extortion|double extortion|ransom demand|data leak site|leak site)\b/i],
];

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const worse = (a, b) => ((SEV_RANK[a] || 0) >= (SEV_RANK[b] || 0) ? a : b);
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const EXPLOITED_RE = /\b(actively exploited|exploited in the wild|under active exploitation|zero-day)\b/i;

function techniqueBase(id) { return String(id).toUpperCase().split('.')[0]; }

/**
 * @param {Array} articles rows with id,title,description,severity,threat_actors,
 *   mitre_ids,sector,cve_id,has_poc,is_patched,tags,published_date
 * @param {number} days
 */
function buildLandscape(articles, days) {
  const tech = new Map();      // id -> {explicit, inferred, worst, samples}
  const tacticCounts = new Map();
  const actors = new Map();
  const cves = new Map();
  const sectors = new Map();
  let mapped = 0, explicitArticles = 0;

  const sample = (list, a) => { if (list.length < 3) list.push({ id: a.id, title: String(a.title || '').slice(0, 140) }); };

  for (const a of articles) {
    const text = `${a.title || ''}\n${a.description || ''}`;
    const sev = a.severity || 'low';

    // ── ATT&CK ──
    const explicit = new Set();
    for (const raw of String(a.mitre_ids || '').split(',')) {
      const id = raw.trim().toUpperCase();
      if (/^T\d{4}/.test(id)) explicit.add(techniqueBase(id));
    }
    const inferred = new Map();   // id -> phrase that matched (doubles as the feed search term)
    for (const [id, re] of INFER) {
      if (explicit.has(id)) continue;
      const m = re.exec(text);
      if (m) inferred.set(id, String(m[1] || m[0]).trim().slice(0, 40));
    }
    if (/Ransomware Leak/i.test(a.title || '') && !explicit.has('T1657') && !inferred.has('T1657')) inferred.set('T1657', 'Ransomware Leak');
    if (explicit.size) explicitArticles++;
    if (explicit.size || inferred.size) mapped++;
    const tacticsHit = new Set();
    for (const [ids, kind] of [[[...explicit].map((id) => [id, id]), 'explicit'], [[...inferred.entries()], 'inferred']]) {
      for (const [id, term] of ids) {
        let t = tech.get(id);
        if (!t) { t = { id, explicit: 0, inferred: 0, worst: 'low', samples: [], terms: new Map() }; tech.set(id, t); }
        t[kind]++;
        const key = kind === 'explicit' ? id : term.toLowerCase();
        t.terms.set(key, (t.terms.get(key) || 0) + 1);
        t.worst = worse(sev, t.worst);
        sample(t.samples, a);
        const meta = TECHNIQUES[id];
        if (meta) tacticsHit.add(meta[1]);
      }
    }
    for (const ta of tacticsHit) tacticCounts.set(ta, (tacticCounts.get(ta) || 0) + 1);

    // ── Threat actors ──
    const names = String(a.threat_actors || '').split(',').map((s) => s.trim()).filter(Boolean);
    const origins = geo.originsOf(names);
    const articleCves = new Set([...(text.match(CVE_RE) || []), ...(a.cve_id ? [a.cve_id] : [])].map((c) => c.toUpperCase()));
    for (const name of names) {
      const key = name.toLowerCase();
      let r = actors.get(key);
      if (!r) { r = { name, count: 0, worst: 'low', lastSeen: null, origin: null, sectors: new Map(), cves: new Set(), samples: [] }; actors.set(key, r); }
      r.count++;
      r.worst = worse(sev, r.worst);
      if (!r.lastSeen || String(a.published_date) > r.lastSeen) r.lastSeen = a.published_date;
      for (const [code, actor] of origins) if (actor === name) r.origin = code;
      if (a.sector) r.sectors.set(a.sector, (r.sectors.get(a.sector) || 0) + 1);
      articleCves.forEach((c) => r.cves.add(c));
      sample(r.samples, a);
    }

    // ── Vulnerabilities ──
    const tags = String(a.tags || '').toLowerCase();
    const exploited = /cisa-kev|actively-exploited/.test(tags) || EXPLOITED_RE.test(text);
    for (const id of articleCves) {
      let c = cves.get(id);
      if (!c) { c = { id, count: 0, worst: 'low', kev: false, exploited: false, poc: false, patched: 0, unpatched: 0, lastSeen: null, title: '' }; cves.set(id, c); }
      c.count++;
      c.worst = worse(sev, c.worst);
      if (/cisa-kev/.test(tags)) c.kev = true;
      if (exploited) c.exploited = true;
      if (a.has_poc) c.poc = true;
      if (a.is_patched === 1) c.patched++;
      if (a.is_patched === 0) c.unpatched++;
      if (!c.lastSeen || String(a.published_date) > c.lastSeen) { c.lastSeen = a.published_date; c.title = String(a.title || '').slice(0, 140); }
    }

    // ── Sectors ──
    if (a.sector) {
      let s = sectors.get(a.sector);
      if (!s) { s = { name: a.sector, count: 0, critical: 0, high: 0 }; sectors.set(a.sector, s); }
      s.count++;
      if (sev === 'critical') s.critical++;
      if (sev === 'high') s.high++;
    }
  }

  // Matrix: every tactic column, techniques sorted by total
  const techList = [...tech.values()].map(({ terms, ...t }) => {
    const meta = TECHNIQUES[t.id];
    const isId = (k) => /^T\d{4}/.test(k);
    const term = [...terms.entries()].sort((x, y) => y[1] - x[1] || isId(x[0]) - isId(y[0]))[0][0];
    return { ...t, name: meta ? meta[0] : t.id, tactic: meta ? meta[1] : null, total: t.explicit + t.inferred, term };
  }).sort((x, y) => y.total - x.total || y.explicit - x.explicit);
  const tactics = TACTICS.map(([id, name]) => ({
    id, name, count: tacticCounts.get(id) || 0,
    techniques: techList.filter((t) => t.tactic === id).slice(0, 8),
  }));
  const unmapped = techList.filter((t) => !t.tactic).slice(0, 12); // explicit IDs outside the catalogue

  const actorList = [...actors.values()]
    .sort((x, y) => y.count - x.count)
    .slice(0, 15)
    .map((r) => ({
      name: r.name, count: r.count, worst: r.worst, lastSeen: r.lastSeen,
      origin: r.origin ? { code: r.origin, name: (geo.COUNTRIES.find((c) => c[0] === r.origin) || [])[1] || r.origin } : null,
      sectors: [...r.sectors.entries()].sort((x, y) => y[1] - x[1]).map(([s]) => s).slice(0, 3),
      cves: [...r.cves].slice(0, 3),
      samples: r.samples,
    }));

  const cveList = [...cves.values()]
    .sort((x, y) => (y.exploited - x.exploited) || (SEV_RANK[y.worst] - SEV_RANK[x.worst]) || (y.count - x.count))
    .slice(0, 15)
    .map((c) => ({ ...c, patch: c.patched && !c.unpatched ? 'patched' : c.unpatched ? 'unpatched' : 'unknown' }));

  const g = geo.buildGeo(articles, days);

  return {
    days,
    totalArticles: articles.length,
    attack: { tactics, unmapped, mappedArticles: mapped, explicitArticles, techniqueCount: techList.length },
    actors: actorList,
    cves: cveList,
    sectors: [...sectors.values()].sort((x, y) => y.count - x.count),
    countries: g.countries.slice(0, 12).map(({ code, name, count, critical, high, term }) => ({ code, name, count, critical, high, term })),
    geolocated: g.geolocated,
    generatedAt: new Date().toISOString(),
  };
}

module.exports = { buildLandscape, TACTICS, TECHNIQUES, INFER };
