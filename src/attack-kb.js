/**
 * ThreatPulse — MITRE ATT&CK knowledge used across the app.
 *
 * - Tactics (Enterprise, kill-chain order) and a technique catalogue with links
 * - Behaviour -> technique inference rules (conservative, phrase-based)
 * - analyzeTtps(): per-report TTPs = Tactic, Technique, and the Procedure (the
 *   sentence in the report that shows it), marked "cited" when the report
 *   names the technique ID and "inferred" when it only describes the behaviour
 */

// Enterprise ATT&CK tactics in kill-chain order
const TACTICS = [
  ['TA0043', 'Reconnaissance'], ['TA0042', 'Resource Development'], ['TA0001', 'Initial Access'],
  ['TA0002', 'Execution'], ['TA0003', 'Persistence'], ['TA0004', 'Privilege Escalation'],
  ['TA0005', 'Defense Evasion'], ['TA0006', 'Credential Access'], ['TA0007', 'Discovery'],
  ['TA0008', 'Lateral Movement'], ['TA0009', 'Collection'], ['TA0011', 'Command and Control'],
  ['TA0010', 'Exfiltration'], ['TA0040', 'Impact'],
];

// Technique catalogue: id -> { name, tactic, desc }. Techniques that belong to
// several tactics are listed under the one they are most often reported for.
// Descriptions are short summaries; the MITRE page is the authoritative source.
const TECHNIQUES = {
  T1620: { name: 'Reflective Code Loading', tactic: 'TA0005', desc: 'Loading code straight into a process\'s memory to avoid writing it to disk.' },
  T1665: { name: 'Hide Infrastructure', tactic: 'TA0011', desc: 'Masking or filtering command-and-control infrastructure to avoid detection and takedown.' },
  T1595: { name: 'Active Scanning', tactic: 'TA0043', desc: 'Probing victim infrastructure (ports, services, vulnerabilities) to find targets.' },
  T1592: { name: 'Gather Victim Host Information', tactic: 'TA0043', desc: 'Collecting details about victim hosts such as software, configuration and hardware.' },
  T1589: { name: 'Gather Victim Identity Information', tactic: 'TA0043', desc: 'Collecting names, emails and credentials of people at the target.' },
  T1598: { name: 'Phishing for Information', tactic: 'TA0043', desc: 'Deceptive messages used to elicit sensitive information rather than run code.' },
  T1583: { name: 'Acquire Infrastructure', tactic: 'TA0042', desc: 'Buying or renting domains, servers, botnets or hosting for operations.' },
  T1584: { name: 'Compromise Infrastructure', tactic: 'TA0042', desc: 'Taking over third-party servers, routers or sites to use as operational infrastructure.' },
  T1587: { name: 'Develop Capabilities', tactic: 'TA0042', desc: 'Building own malware, exploits or tooling.' },
  T1588: { name: 'Obtain Capabilities', tactic: 'TA0042', desc: 'Buying, stealing or downloading malware, exploits or tools.' },
  T1608: { name: 'Stage Capabilities', tactic: 'TA0042', desc: 'Uploading tools or payloads to infrastructure ahead of use.' },
  T1650: { name: 'Acquire Access', tactic: 'TA0042', desc: 'Purchasing existing access to victim networks, e.g. from initial access brokers.' },
  T1566: { name: 'Phishing', tactic: 'TA0001', desc: 'Malicious emails or messages with attachments or links to gain a foothold.' },
  T1190: { name: 'Exploit Public-Facing Application', tactic: 'TA0001', desc: 'Exploiting a flaw in an internet-facing system such as a VPN, firewall or web server.' },
  T1195: { name: 'Supply Chain Compromise', tactic: 'TA0001', desc: 'Tampering with software, packages or updates before they reach the victim.' },
  T1133: { name: 'External Remote Services', tactic: 'TA0001', desc: 'Using VPN, RDP or other remote services to get in, often with stolen credentials.' },
  T1078: { name: 'Valid Accounts', tactic: 'TA0001', desc: 'Logging in with legitimate, stolen or leaked credentials.' },
  T1189: { name: 'Drive-by Compromise', tactic: 'TA0001', desc: 'Compromising users who browse to a malicious or injected website.' },
  T1199: { name: 'Trusted Relationship', tactic: 'TA0001', desc: 'Abusing access held by a supplier, MSP or other trusted third party.' },
  T1091: { name: 'Replication Through Removable Media', tactic: 'TA0001', desc: 'Spreading via infected USB or other removable drives.' },
  T1059: { name: 'Command and Scripting Interpreter', tactic: 'TA0002', desc: 'Running commands or scripts through PowerShell, shells, VBScript, Python and similar.' },
  T1204: { name: 'User Execution', tactic: 'TA0002', desc: 'Tricking a user into opening a file or running something (lures, fake CAPTCHAs).' },
  T1203: { name: 'Exploitation for Client Execution', tactic: 'TA0002', desc: 'Exploiting a browser, document reader or other client application to run code.' },
  T1047: { name: 'Windows Management Instrumentation', tactic: 'TA0002', desc: 'Using WMI to execute commands locally or remotely.' },
  T1053: { name: 'Scheduled Task/Job', tactic: 'TA0003', desc: 'Using scheduled tasks or cron jobs to run code repeatedly or at startup.' },
  T1547: { name: 'Boot or Logon Autostart Execution', tactic: 'TA0003', desc: 'Registry run keys, startup folders or launch agents that start malware at boot or logon.' },
  T1505: { name: 'Server Software Component', tactic: 'TA0003', desc: 'Planting web shells or malicious server modules for persistent access.' },
  T1543: { name: 'Create or Modify System Process', tactic: 'TA0003', desc: 'Installing malicious services or daemons.' },
  T1176: { name: 'Browser Extensions', tactic: 'TA0003', desc: 'Malicious browser extensions for persistence or data theft.' },
  T1136: { name: 'Create Account', tactic: 'TA0003', desc: 'Creating new accounts to keep access.' },
  T1068: { name: 'Exploitation for Privilege Escalation', tactic: 'TA0004', desc: 'Exploiting a software flaw to gain higher privileges.' },
  T1548: { name: 'Abuse Elevation Control Mechanism', tactic: 'TA0004', desc: 'Bypassing UAC, sudo or similar elevation controls.' },
  T1562: { name: 'Impair Defenses', tactic: 'TA0005', desc: 'Disabling or tampering with security tools, often with vulnerable drivers (BYOVD).' },
  T1027: { name: 'Obfuscated Files or Information', tactic: 'TA0005', desc: 'Encoding, packing or encrypting payloads to hide them.' },
  T1055: { name: 'Process Injection', tactic: 'TA0005', desc: 'Running code inside another process to evade defenses.' },
  T1218: { name: 'System Binary Proxy Execution', tactic: 'TA0005', desc: 'Using trusted system binaries (rundll32, mshta, regsvr32) to run malicious code.' },
  T1574: { name: 'Hijack Execution Flow', tactic: 'TA0005', desc: 'DLL side-loading or search-order hijacking to run malicious code.' },
  T1036: { name: 'Masquerading', tactic: 'TA0005', desc: 'Disguising malware as legitimate software, updates or files.' },
  T1553: { name: 'Subvert Trust Controls', tactic: 'TA0005', desc: 'Signing malware or abusing certificates so it looks trusted.' },
  T1014: { name: 'Rootkit', tactic: 'TA0005', desc: 'Hiding malicious activity at kernel or boot level.' },
  T1070: { name: 'Indicator Removal', tactic: 'TA0005', desc: 'Clearing logs or deleting artifacts to cover tracks.' },
  T1497: { name: 'Virtualization/Sandbox Evasion', tactic: 'TA0005', desc: 'Detecting analysis environments and changing behaviour to avoid them.' },
  T1003: { name: 'OS Credential Dumping', tactic: 'TA0006', desc: 'Extracting credentials from memory or system stores such as LSASS or NTDS.dit.' },
  T1110: { name: 'Brute Force', tactic: 'TA0006', desc: 'Guessing passwords, including password spraying and credential stuffing.' },
  T1555: { name: 'Credentials from Password Stores', tactic: 'TA0006', desc: 'Stealing saved passwords from browsers and password managers (typical of infostealers).' },
  T1539: { name: 'Steal Web Session Cookie', tactic: 'TA0006', desc: 'Stealing session cookies or tokens to hijack logged-in sessions.' },
  T1557: { name: 'Adversary-in-the-Middle', tactic: 'TA0006', desc: 'Intercepting traffic or logins, e.g. AiTM phishing proxies that capture MFA sessions.' },
  T1621: { name: 'Multi-Factor Authentication Request Generation', tactic: 'TA0006', desc: 'Flooding users with MFA prompts until one is approved.' },
  T1056: { name: 'Input Capture', tactic: 'TA0006', desc: 'Keylogging, form-grabbing or skimming to capture credentials and card data.' },
  T1552: { name: 'Unsecured Credentials', tactic: 'TA0006', desc: 'Finding passwords or keys left in files, code or configuration.' },
  T1082: { name: 'System Information Discovery', tactic: 'TA0007', desc: 'Collecting details about the compromised system.' },
  T1046: { name: 'Network Service Discovery', tactic: 'TA0007', desc: 'Scanning the internal network for services and hosts.' },
  T1087: { name: 'Account Discovery', tactic: 'TA0007', desc: 'Listing users and accounts in the environment.' },
  T1083: { name: 'File and Directory Discovery', tactic: 'TA0007', desc: 'Browsing files and directories to find data of interest.' },
  T1021: { name: 'Remote Services', tactic: 'TA0008', desc: 'Moving between hosts with RDP, SMB, SSH or PsExec.' },
  T1570: { name: 'Lateral Tool Transfer', tactic: 'TA0008', desc: 'Copying tools between hosts inside the network.' },
  T1114: { name: 'Email Collection', tactic: 'TA0009', desc: 'Accessing mailboxes to collect email.' },
  T1113: { name: 'Screen Capture', tactic: 'TA0009', desc: 'Taking screenshots of the victim desktop.' },
  T1005: { name: 'Data from Local System', tactic: 'TA0009', desc: 'Collecting files and data from compromised hosts.' },
  T1560: { name: 'Archive Collected Data', tactic: 'TA0009', desc: 'Compressing or encrypting collected data before exfiltration.' },
  T1071: { name: 'Application Layer Protocol', tactic: 'TA0011', desc: 'Command-and-control over web, DNS or other common protocols (e.g. Cobalt Strike beacons).' },
  T1090: { name: 'Proxy', tactic: 'TA0011', desc: 'Routing traffic through proxies or proxy networks to hide its origin.' },
  T1572: { name: 'Protocol Tunneling', tactic: 'TA0011', desc: 'Tunnelling traffic through DNS, SSH or services like ngrok.' },
  T1219: { name: 'Remote Access Software', tactic: 'TA0011', desc: 'Abusing legitimate remote-access or RMM tools such as AnyDesk or ScreenConnect.' },
  T1105: { name: 'Ingress Tool Transfer', tactic: 'TA0011', desc: 'Downloading additional tools or payloads onto a compromised host.' },
  T1102: { name: 'Web Service', tactic: 'TA0011', desc: 'Using legitimate web services (Telegram, Discord, cloud) for command and control.' },
  T1041: { name: 'Exfiltration Over C2 Channel', tactic: 'TA0010', desc: 'Sending stolen data out over the command-and-control channel.' },
  T1567: { name: 'Exfiltration Over Web Service', tactic: 'TA0010', desc: 'Uploading stolen data to cloud storage or file-sharing services.' },
  T1048: { name: 'Exfiltration Over Alternative Protocol', tactic: 'TA0010', desc: 'Exfiltrating data over a protocol other than the C2 channel.' },
  T1486: { name: 'Data Encrypted for Impact', tactic: 'TA0040', desc: 'Encrypting data or systems to disrupt operations, as ransomware does.' },
  T1490: { name: 'Inhibit System Recovery', tactic: 'TA0040', desc: 'Deleting backups or shadow copies to prevent recovery.' },
  T1485: { name: 'Data Destruction', tactic: 'TA0040', desc: 'Destroying data, for example with wiper malware.' },
  T1498: { name: 'Network Denial of Service', tactic: 'TA0040', desc: 'Flooding networks or services to make them unavailable (DDoS).' },
  T1499: { name: 'Endpoint Denial of Service', tactic: 'TA0040', desc: 'Crashing or exhausting a system or application to deny service.' },
  T1491: { name: 'Defacement', tactic: 'TA0040', desc: 'Altering website or system content visibly.' },
  T1496: { name: 'Resource Hijacking', tactic: 'TA0040', desc: 'Using victim resources for cryptomining or proxying.' },
  T1657: { name: 'Financial Theft', tactic: 'TA0040', desc: 'Stealing money or extorting victims, including ransom and leak-site extortion.' },
  T1489: { name: 'Service Stop', tactic: 'TA0040', desc: 'Stopping services to disrupt operations or enable encryption.' },
  T1565: { name: 'Data Manipulation', tactic: 'TA0040', desc: 'Altering data to affect business processes or decisions.' },
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

// Common aliases folded into one actor (display name = canonical; aliases listed)
const ACTOR_ALIASES = {
  'lazarus group': 'Lazarus', 'apt38': 'Lazarus',
  'fancy bear': 'APT28', 'forest blizzard': 'APT28',
  'cozy bear': 'APT29', 'midnight blizzard': 'APT29', 'unc2452': 'APT29', 'nobelium': 'APT29',
  'voodoo bear': 'Sandworm', 'seashell blizzard': 'Sandworm',
  'charming kitten': 'APT35', 'helix kitten': 'APT34', 'oilrig': 'APT34',
  'wicked panda': 'APT41', 'emissary panda': 'APT27', 'hafnium': 'Silk Typhoon',
  'alphv': 'BlackCat', 'clop': 'Cl0p', 'star blizzard': 'Star Blizzard', 'cold river': 'Star Blizzard', 'coldriver': 'Star Blizzard',
  'scattered spider': 'Scattered Spider', 'octo tempest': 'Scattered Spider', 'unc3944': 'Scattered Spider',
};
const canonicalActor = (name) => ACTOR_ALIASES[name.toLowerCase()] || name;


const TACTIC_NAME = Object.fromEntries(TACTICS);
const INFER_BY_ID = Object.fromEntries(INFER);
function techniqueBase(id) { return String(id).toUpperCase().split('.')[0]; }

function attackUrl(id) {
  const s = String(id || '').trim().toUpperCase();
  if (/^TA\d{4}$/.test(s)) return `https://attack.mitre.org/tactics/${s}/`;
  const m = s.match(/^T(\d{4})(?:\.(\d{3}))?$/);
  if (!m) return 'https://attack.mitre.org/';
  return m[2] ? `https://attack.mitre.org/techniques/T${m[1]}/${m[2]}/` : `https://attack.mitre.org/techniques/T${m[1]}/`;
}

// Sentence of `text` that contains `needle` (RegExp or string) — the "procedure"
function sentenceWith(text, needle) {
  const parts = String(text || '').split(/(?<=[.!?])\s+|\n+/).map((s) => s.trim()).filter(Boolean);
  const hit = parts.find((p) => (needle instanceof RegExp ? needle.test(p) : p.toUpperCase().includes(String(needle).toUpperCase())));
  if (!hit) return null;
  return hit.length > 220 ? `${hit.slice(0, 217).trimEnd()}…` : hit;
}

/**
 * TTPs for one report.
 * @returns {Array<{id, subId, name, tactic, tacticName, how: 'cited'|'inferred', term, procedure, url}>}
 */
// Prefer a sentence from the body (richer than the headline), then the headline
function procedureFor(title, body, needle) {
  return sentenceWith(body, needle) || sentenceWith(title, needle);
}

function analyzeTtps(article) {
  const title = String(article.title || '');
  const body = String(article.description || '');
  const text = `${title}\n${article.description || ''}`;
  const out = [];
  const seen = new Set();
  for (const raw of String(article.mitre_ids || '').split(',')) {
    const sub = raw.trim().toUpperCase();
    if (!/^T1\d{3}(\.\d{3})?$/.test(sub)) continue;   // real Enterprise IDs only (stored rows may hold older false hits)
    const id = techniqueBase(sub);
    if (seen.has(id)) continue;
    seen.add(id);
    const meta = TECHNIQUES[id];
    out.push({
      id, subId: sub !== id ? sub : null, name: meta ? meta.name : id, tactic: meta ? meta.tactic : null,
      tacticName: meta ? TACTIC_NAME[meta.tactic] : null, desc: meta ? meta.desc : null, how: 'cited', term: sub,
      procedure: (INFER_BY_ID[id] && procedureFor(title, body, INFER_BY_ID[id])) || procedureFor(title, body, sub), url: attackUrl(sub),
    });
  }
  for (const [id, re] of INFER) {
    if (seen.has(id)) continue;
    const m = re.exec(text);
    if (!m) continue;
    // "with no phishing", "not ransomware", "without malware" describe what did NOT happen
    if (/\b(no|not|without|never|non)[\s-]+(\w+\s+){0,1}$/i.test(text.slice(Math.max(0, m.index - 24), m.index))) continue;
    seen.add(id);
    const meta = TECHNIQUES[id];
    const term = String(m[1] || m[0]).trim().slice(0, 40);
    out.push({
      id, subId: null, name: meta.name, tactic: meta.tactic, tacticName: TACTIC_NAME[meta.tactic], desc: meta.desc, how: 'inferred', term,
      procedure: procedureFor(title, body, re) || procedureFor(title, body, term), url: attackUrl(id),
    });
  }
  if (/Ransomware Leak/i.test(title) && !seen.has('T1657')) {
    const meta = TECHNIQUES.T1657;
    out.push({ id: 'T1657', subId: null, name: meta.name, tactic: meta.tactic, tacticName: TACTIC_NAME[meta.tactic], desc: meta.desc, how: 'inferred',
      term: 'Ransomware Leak', procedure: 'Victim listed on a ransomware leak site (extortion).', url: attackUrl('T1657') });
  }
  // kill-chain order
  const order = Object.fromEntries(TACTICS.map(([t], i) => [t, i]));
  return out.sort((a, b) => (order[a.tactic] ?? 99) - (order[b.tactic] ?? 99));
}

module.exports = { TACTICS, TACTIC_NAME, TECHNIQUES, INFER, ACTOR_ALIASES, canonicalActor, techniqueBase, attackUrl, analyzeTtps, sentenceWith };
