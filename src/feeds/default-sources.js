/**
 * ThreatPulse — Default Threat Intelligence Sources
 * 160+ pre-configured, verified feeds from around the world
 */

const DEFAULT_SOURCES = [
  // ============================================
  // 🔴 VULNERABILITY DATABASES & ADVISORIES
  // ============================================
  {
    name: 'NVD - National Vulnerability Database',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    type: 'api',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'CISA Known Exploited Vulnerabilities',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    type: 'api',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Exploit-DB',
    url: 'https://www.exploit-db.com/rss.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },

  // ============================================
  // 📰 CYBERSECURITY NEWS & BLOGS
  // ============================================
  {
    name: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'GBHackers Security',
    url: 'https://gbhackers.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Krebs on Security',
    url: 'https://krebsonsecurity.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Dark Reading',
    url: 'https://www.darkreading.com/rss.xml',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'SecurityWeek',
    url: 'https://www.securityweek.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'The Record by Recorded Future',
    url: 'https://therecord.media/feed',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Infosecurity Magazine',
    url: 'https://www.infosecurity-magazine.com/rss/news/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },

  // ============================================
  // 🏢 VENDOR THREAT INTELLIGENCE
  // ============================================
  {
    name: 'Cisco Talos Blog',
    url: 'https://blog.talosintelligence.com/rss/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Microsoft Security Blog',
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'CrowdStrike Blog',
    url: 'https://www.crowdstrike.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Palo Alto Unit 42',
    url: 'https://unit42.paloaltonetworks.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'SentinelOne Labs',
    url: 'https://www.sentinelone.com/labs/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Kaspersky Securelist',
    url: 'https://securelist.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Zero Day Initiative (Published Advisories)',
    url: 'https://www.zerodayinitiative.com/rss/published/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },

  // ============================================
  // 🛠️ DETECTION ENGINEERING (TTPs · PoCs · MITRE-mapped)
  // ============================================
  {
    name: 'The DFIR Report',
    url: 'https://thedfirreport.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Red Canary',
    url: 'https://redcanary.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Elastic Security Labs',
    url: 'https://www.elastic.co/security-labs/rss/feed.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Rapid7 Blog',
    url: 'https://www.rapid7.com/blog/rss/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Google Project Zero',
    url: 'https://googleprojectzero.blogspot.com/feeds/posts/default',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Huntress Blog',
    url: 'https://www.huntress.com/blog/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },

  // ============================================
  // 🌑 DARK WEB & UNDERGROUND INTEL (Clearnet APIs)
  // ============================================
  {
    name: 'RansomWatch - Ransomware Leak Tracker',
    url: 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'URLhaus - Malicious URLs',
    url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'ThreatFox - Malware IOCs',
    url: 'https://threatfox-api.abuse.ch/api/v1/',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'MalwareBazaar - Malware Samples',
    url: 'https://mb-api.abuse.ch/api/v1/',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'Feodo Tracker - Botnet C2s',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },

  // ============================================
  // 🐦 COMMUNITY & SOCIAL
  // ============================================
  {
    name: 'SANS Internet Storm Center',
    url: 'https://isc.sans.edu/rssfeed.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },

  // ============================================
  // 🏛️ GOVERNMENT & CERT ADVISORIES (Worldwide)
  // ============================================
  {
    name: 'CISA Alerts (USA)',
    url: 'https://www.cisa.gov/news.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CERT-EU (European Union)',
    url: 'https://cert.europa.eu/publications/security-advisories-rss',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CERT-FR ANSSI Alerts (France)',
    url: 'https://www.cert.ssi.gouv.fr/alerte/feed/',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'JPCERT/CC (Japan)',
    url: 'https://www.jpcert.or.jp/english/rss/jpcert-en.rdf',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'JPCERT Blog (Japan)',
    url: 'https://blogs.jpcert.or.jp/en/atom.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CIS/MS-ISAC Advisories (USA)',
    url: 'https://www.cisecurity.org/feed/advisories',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: '0patch Blog',
    url: 'https://blog.0patch.com/feeds/posts/default',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Assetnote Research',
    url: 'https://blog.assetnote.io/feed.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Bishop Fox',
    url: 'https://bishopfox.com/feeds/blog.rss',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Darknet.org.uk',
    url: 'https://www.darknet.org.uk/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Doyensec',
    url: 'https://blog.doyensec.com/atom.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'GitHub Security Lab',
    url: 'https://github.blog/tag/github-security-lab/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Include Security',
    url: 'https://blog.includesecurity.com/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'JFrog Security Research',
    url: 'https://jfrog.com/blog/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Legit Security Blog',
    url: 'https://www.legitsecurity.com/blog/rss.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Nuclei Templates Releases',
    url: 'https://github.com/projectdiscovery/nuclei-templates/releases.atom',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Patchstack Blog',
    url: 'https://patchstack.com/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'PoC-in-GitHub Tracker',
    url: 'https://github.com/nomi-sec/PoC-in-GitHub/commits/master.atom',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'PortSwigger Research',
    url: 'https://portswigger.net/research/rss',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'ProjectDiscovery Blog',
    url: 'https://blog.projectdiscovery.io/rss/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'PT SWARM (Positive Technologies)',
    url: 'https://swarm.ptsecurity.com/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Qualys Blog',
    url: 'https://blog.qualys.com/feed',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Rapid7 Emergent Threats',
    url: 'https://www.rapid7.com/blog/tag/emergent-threat-response/rss/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Rapid7 Vuln Disclosures',
    url: 'https://www.rapid7.com/blog/tag/vulnerability-disclosure/rss/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Rhino Security Labs',
    url: 'https://rhinosecuritylabs.com/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'runZero Blog',
    url: 'https://www.runzero.com/blog/index.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'SensePost (Orange Cyberdefense)',
    url: 'https://sensepost.com/rss.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'SNYK Security Blog',
    url: 'https://snyk.io/blog/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'SonarSource Blog',
    url: 'https://www.sonarsource.com/blog/rss.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'STAR Labs SG',
    url: 'https://starlabs.sg/blog/index.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Tenable Blog',
    url: 'https://www.tenable.com/blog/feed',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Trickest CVE PoCs',
    url: 'https://github.com/trickest/cve/commits/main.atom',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Wallarm Lab',
    url: 'https://lab.wallarm.com/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'watchTowr Labs',
    url: 'https://labs.watchtowr.com/rss/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'WordFence Blog',
    url: 'https://www.wordfence.com/feed/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'ZDI Upcoming Advisories',
    url: 'https://www.zerodayinitiative.com/rss/upcoming/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Aqua Nautilus',
    url: 'https://blog.aquasec.com/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'AttackIQ Blog',
    url: 'https://www.attackiq.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Bitdefender Labs',
    url: 'https://www.bitdefender.com/blog/api/rss/labs/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Black Hills InfoSec',
    url: 'https://www.blackhillsinfosec.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Check Point Blog',
    url: 'https://blog.checkpoint.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Check Point Research',
    url: 'https://research.checkpoint.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Cloudflare Blog',
    url: 'https://blog.cloudflare.com/rss/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Cofense',
    url: 'https://cofense.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Corelight Blog',
    url: 'https://corelight.com/blog/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Cybereason Blog',
    url: 'https://www.cybereason.com/blog/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Cyble Blog',
    url: 'https://cyble.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Datadog Security Labs',
    url: 'https://securitylabs.datadoghq.com/rss/feed.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Detection Engineering Weekly',
    url: 'https://www.detectionengineering.net/feed',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'EclecticIQ Blog',
    url: 'https://blog.eclecticiq.com/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Elastic Detection Rules Releases',
    url: 'https://github.com/elastic/detection-rules/releases.atom',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'ESET WeLiveSecurity',
    url: 'https://www.welivesecurity.com/en/rss/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Fortinet Threat Research',
    url: 'https://feeds.fortinet.com/fortinet/blog/threat-research',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Fox-IT International',
    url: 'https://blog.fox-it.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'GitGuardian Blog',
    url: 'https://blog.gitguardian.com/rss/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Google Security Blog',
    url: 'https://security.googleblog.com/feeds/posts/default',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'GreyNoise Labs',
    url: 'https://www.greynoise.io/blog/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'GTFOBins',
    url: 'https://github.com/GTFOBins/GTFOBins.github.io/commits/master.atom',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Hexacorn',
    url: 'http://www.hexacorn.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Intel471 Blog',
    url: 'https://intel471.com/blog/feed',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'KnowBe4 Security Blog',
    url: 'https://blog.knowbe4.com/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Kraven Security',
    url: 'https://kravensecurity.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'LOLBAS Project',
    url: 'https://github.com/LOLBAS-Project/LOLBAS/commits/master.atom',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Malwarebytes Labs',
    url: 'https://www.malwarebytes.com/blog/feed/index.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'MITRE ATT&CK Blog',
    url: 'https://medium.com/feed/mitre-attack',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'MITRE Engenuity',
    url: 'https://medium.com/feed/mitre-engenuity',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Netskope Threat Labs',
    url: 'https://www.netskope.com/blog/feed',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Nextron Systems',
    url: 'https://www.nextron-systems.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Palo Alto Networks Blog',
    url: 'https://www.paloaltonetworks.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Pen Test Partners',
    url: 'https://www.pentestpartners.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Praetorian Blog',
    url: 'https://www.praetorian.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Proofpoint Threat Insight',
    url: 'https://www.proofpoint.com/us/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Recorded Future Blog',
    url: 'https://www.recordedfuture.com/feed',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Securelist APT Reports',
    url: 'https://securelist.com/category/apt-reports/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Security Onion Blog',
    url: 'https://blog.securityonion.net/feeds/posts/default',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'SentinelOne Blog',
    url: 'https://www.sentinelone.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Sigma Rules Releases',
    url: 'https://github.com/SigmaHQ/sigma/releases.atom',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'SOC Prime Blog',
    url: 'https://socprime.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Sophos X-Ops',
    url: 'https://news.sophos.com/en-us/category/threat-research/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Splunk Security Content Releases',
    url: 'https://github.com/splunk/security_content/releases.atom',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Sysdig Blog',
    url: 'https://sysdig.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'This Week in 4n6',
    url: 'https://thisweekin4n6.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'tl;dr sec',
    url: 'https://tldrsec.com/feed.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'TrustedSec',
    url: 'https://www.trustedsec.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Uptycs Blog',
    url: 'https://www.uptycs.com/blog/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'WeLiveSecurity',
    url: 'https://feeds.feedburner.com/eset/blog',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'WeLiveSecurity Research',
    url: 'https://www.welivesecurity.com/category/research/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Wiz Blog',
    url: 'https://www.wiz.io/blog/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Zscaler ThreatLabz',
    url: 'https://www.zscaler.com/blogs/feeds/security-research',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'AhnLab ASEC Blog',
    url: 'https://asec.ahnlab.com/en/feed/',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Aikido Security Blog',
    url: 'https://www.aikido.dev/blog/rss.xml',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'ANY.RUN Blog',
    url: 'https://any.run/cybersecurity-blog/feed/',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Didier Stevens',
    url: 'https://blog.didierstevens.com/feed/',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Embee Research',
    url: 'https://www.embeeresearch.io/rss/',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Jamf Threat Labs',
    url: 'https://www.jamf.com/blog/rss/',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Kandji Threat Research',
    url: 'https://www.kandji.io/blog/rss.xml',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Koi Security',
    url: 'https://www.koi.security/blog/rss.xml',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Malware Traffic Analysis',
    url: 'https://www.malware-traffic-analysis.net/blog-entries.rss',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'MalwareTech',
    url: 'https://malwaretech.com/feed',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'OALABS Research',
    url: 'https://research.openanalysis.net/feed.xml',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Objective-See (macOS)',
    url: 'https://objective-see.org/rss.xml',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'ReversingLabs Blog',
    url: 'https://www.reversinglabs.com/blog/rss.xml',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Sucuri Blog',
    url: 'https://blog.sucuri.net/feed',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'Volatility Labs',
    url: 'https://volatility-labs.blogspot.com/feeds/posts/default',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },
  {
    name: 'CERT-EU Threat Intel',
    url: 'https://cert.europa.eu/publications/threat-intelligence-rss',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CERT-PL',
    url: 'https://cert.pl/en/rss.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'Chrome Releases',
    url: 'https://chromereleases.googleblog.com/feeds/posts/default',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CIRCL Luxembourg',
    url: 'https://www.circl.lu/rss.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CISA All Advisories',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CISA Cybersecurity Advisories',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml?page&type%5B0%5D=advisories',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CISA ICS Advisories',
    url: 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'Cisco Security Advisories (PSIRT)',
    url: 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'Fortinet FortiGuard',
    url: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'NCSC UK',
    url: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'Ubuntu Security Notices',
    url: 'https://ubuntu.com/security/notices/rss.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CyberScoop',
    url: 'https://cyberscoop.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Cybersecurity Dive',
    url: 'https://www.cybersecuritydive.com/feeds/news/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Graham Cluley',
    url: 'https://grahamcluley.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Hackread',
    url: 'https://www.hackread.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Help Net Security',
    url: 'https://www.helpnetsecurity.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Industrial Cyber',
    url: 'https://industrialcyber.co/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Risky Business News',
    url: 'https://risky.biz/feeds/risky-business-news/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Schneier on Security',
    url: 'https://www.schneier.com/feed/atom/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Security Affairs',
    url: 'https://securityaffairs.com/feed',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'The Cyber Express',
    url: 'https://thecyberexpress.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'The Register Security',
    url: 'https://www.theregister.com/security/headlines.atom',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Unsupervised Learning',
    url: 'https://danielmiessler.com/feed',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Comparitech Security',
    url: 'https://www.comparitech.com/blog/information-security/feed/',
    type: 'rss',
    category: 'breach',
    added_by: 'system'
  },
  {
    name: 'DataBreaches.net',
    url: 'https://databreaches.net/feed/',
    type: 'rss',
    category: 'breach',
    added_by: 'system'
  },
  {
    name: 'Have I Been Pwned Blog',
    url: 'https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches',
    type: 'rss',
    category: 'breach',
    added_by: 'system'
  },
  {
    name: 'Troy Hunt',
    url: 'https://www.troyhunt.com/rss/',
    type: 'rss',
    category: 'breach',
    added_by: 'system'
  },
  {
    name: 'Flashpoint',
    url: 'https://flashpoint.io/feed/',
    type: 'rss',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'S2W Blog',
    url: 'https://medium.com/feed/s2wblog',
    type: 'rss',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'SOCRadar Blog',
    url: 'https://socradar.io/feed/',
    type: 'rss',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'Red Siege',
    url: 'https://redsiege.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Qi An Xin XLab',
    url: 'https://blog.xlab.qianxin.com/rss/',
    type: 'rss',
    category: 'malware',
    added_by: 'system'
  },

  // ============================================
  // BROWSER-FETCHED (Cloudflare/Akamai protected — needs headless Chrome)
  // ============================================
  {
    name: 'Outpost24 Blog',
    url: 'https://outpost24.com/blog/feed/',
    type: 'browser',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Tripwire State of Security',
    url: 'https://www.tripwire.com/state-of-security/feed/',
    type: 'browser',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Security Boulevard',
    url: 'https://securityboulevard.com/feed/',
    type: 'browser',
    category: 'news',
    added_by: 'system'
  }
];

// System sources that were removed because their feeds are permanently broken.
// These are cleaned up from existing installs on startup.
const OBSOLETE_SOURCES = [
  'CCCS (Canada)',
  'BSI (Germany)',
  'Google/Mandiant Threat Intel',
  'Trend Micro Research', // replaced by the correctly-labelled ZDI entry
  // Legacy feeds that are permanently dead (404 / bot-blocked / rate-limited)
  'HackerOne Blog',
  'Reddit r/netsec',
  'Reddit r/malware',
  'SC Magazine',
  'Sophos News', // nakedsecurity retired; news.sophos feed returns 404
];

function seedDefaultSources(db) {
  const database = typeof db.addSource === 'function' ? db : require('../database');
  let added = 0, updated = 0, skipped = 0, removed = 0;

  // 1. Remove obsolete/broken system sources FIRST, so renamed replacements
  //    (which may reuse the same feed URL) can be added cleanly afterwards.
  for (const s of database.getAllSources()) {
    if (OBSOLETE_SOURCES.includes(s.name) && (s.added_by === 'system' || !s.user_id)) {
      const res = database.deleteSource(s.id);
      if (res.success) removed++;
    }
  }

  // 2. Add new defaults / fix relocated URLs on existing system sources
  const allSources = database.getAllSources();
  for (const source of DEFAULT_SOURCES) {
    const byName = allSources.find(s => s.name === source.name);
    const byUrl = allSources.find(s => s.url === source.url);

    if (byName) {
      // Same source, but the feed URL moved — repair it in place
      if (byName.url !== source.url && (byName.added_by === 'system' || !byName.user_id)) {
        database.updateSource(byName.id, { url: source.url, type: source.type, category: source.category });
        updated++;
      } else {
        skipped++;
      }
      continue;
    }
    if (byUrl) { skipped++; continue; }

    const result = database.addSource(source);
    if (result.success) added++; else skipped++;
  }

  // 3. De-duplicate system sources that share a name (legacy installs sometimes
  //    accumulated duplicates with slightly different/stale URLs). Keep the row whose
  //    URL matches a current default (else the lowest id); delete the rest.
  const defaultUrls = new Set(DEFAULT_SOURCES.map(s => s.url));
  const byName = {};
  for (const s of database.getAllSources()) {
    if (!(s.added_by === 'system' || !s.user_id)) continue;
    const key = s.name.trim().toLowerCase();
    (byName[key] = byName[key] || []).push(s);
  }
  for (const key of Object.keys(byName)) {
    const rows = byName[key].sort((a, b) => a.id - b.id);
    if (rows.length < 2) continue;
    const keep = rows.find(r => defaultUrls.has(r.url)) || rows[0];
    for (const r of rows) {
      if (r.id !== keep.id) {
        const res = database.deleteSource(r.id);
        if (res.success) removed++;
      }
    }
  }

  console.log(`[Sources] Seeded ${added} new, fixed ${updated}, removed ${removed} obsolete/dupe, ${skipped} unchanged`);
  return { added, updated, removed, skipped, total: DEFAULT_SOURCES.length };
}

module.exports = { DEFAULT_SOURCES, seedDefaultSources };
