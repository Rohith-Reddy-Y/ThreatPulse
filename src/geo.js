/**
 * ThreatPulse — threat geography.
 *
 * Turns a user's own articles into country-level signals for the 3D globe:
 *  - countries named in a report (names, demonyms, ISO codes from ransomware
 *    leak-site data) → per-country counts and worst severity
 *  - attributed threat actors → commonly reported country of origin
 *  - origin → named target pairs → arcs
 *
 * Pure text matching on data the user can already see; nothing is fetched.
 * Attribution follows public vendor naming (e.g. CrowdStrike: Bear = Russia,
 * Panda = China, Kitten = Iran, Chollima = North Korea) and is labelled as
 * "attributed" in the UI, never as fact.
 */

// [ISO2, display name, lat, lon, extra aliases (regex-safe words)]
const COUNTRIES = [
  ['US', 'United States', 38.9, -77.0, ['United States', 'American', 'Americans', 'U\\.S\\.A?\\.?', 'USA', 'US']],
  ['CA', 'Canada', 45.4, -75.7, ['Canadian']],
  ['MX', 'Mexico', 19.4, -99.1, ['Mexican']],
  ['BR', 'Brazil', -15.8, -47.9, ['Brazilian']],
  ['AR', 'Argentina', -34.6, -58.4, ['Argentine', 'Argentinian']],
  ['CL', 'Chile', -33.4, -70.6, ['Chilean']],
  ['CO', 'Colombia', 4.7, -74.1, ['Colombian']],
  ['PE', 'Peru', -12.0, -77.0, ['Peruvian']],
  ['VE', 'Venezuela', 10.5, -66.9, ['Venezuelan']],
  ['EC', 'Ecuador', -0.2, -78.5, ['Ecuadorian']],
  ['GB', 'United Kingdom', 51.5, -0.1, ['United Kingdom', 'Britain', 'British', 'England', 'Scotland', 'Wales', 'U\\.K\\.', 'UK']],
  ['IE', 'Ireland', 53.3, -6.3, ['Irish']],
  ['FR', 'France', 48.9, 2.35, ['French']],
  ['DE', 'Germany', 52.5, 13.4, ['German']],
  ['NL', 'Netherlands', 52.4, 4.9, ['Dutch', 'Holland']],
  ['BE', 'Belgium', 50.85, 4.35, ['Belgian']],
  ['LU', 'Luxembourg', 49.6, 6.1, []],
  ['CH', 'Switzerland', 46.9, 7.45, ['Swiss']],
  ['AT', 'Austria', 48.2, 16.4, ['Austrian']],
  ['IT', 'Italy', 41.9, 12.5, ['Italian']],
  ['ES', 'Spain', 40.4, -3.7, ['Spanish']],
  ['PT', 'Portugal', 38.7, -9.1, ['Portuguese']],
  ['SE', 'Sweden', 59.3, 18.1, ['Swedish']],
  ['NO', 'Norway', 59.9, 10.75, ['Norwegian']],
  ['DK', 'Denmark', 55.7, 12.6, ['Danish']],
  ['FI', 'Finland', 60.2, 24.9, ['Finnish']],
  ['IS', 'Iceland', 64.1, -21.9, ['Icelandic']],
  ['PL', 'Poland', 52.2, 21.0, ['Polish']],
  ['CZ', 'Czechia', 50.1, 14.4, ['Czech Republic', 'Czech']],
  ['SK', 'Slovakia', 48.15, 17.1, ['Slovak']],
  ['HU', 'Hungary', 47.5, 19.05, ['Hungarian']],
  ['RO', 'Romania', 44.4, 26.1, ['Romanian']],
  ['BG', 'Bulgaria', 42.7, 23.3, ['Bulgarian']],
  ['GR', 'Greece', 37.98, 23.7, ['Greek']],
  ['HR', 'Croatia', 45.8, 16.0, ['Croatian']],
  ['RS', 'Serbia', 44.8, 20.5, ['Serbian']],
  ['SI', 'Slovenia', 46.05, 14.5, ['Slovenian']],
  ['EE', 'Estonia', 59.4, 24.75, ['Estonian']],
  ['LV', 'Latvia', 56.95, 24.1, ['Latvian']],
  ['LT', 'Lithuania', 54.7, 25.3, ['Lithuanian']],
  ['MD', 'Moldova', 47.0, 28.85, ['Moldovan']],
  ['UA', 'Ukraine', 50.45, 30.5, ['Ukrainian']],
  ['BY', 'Belarus', 53.9, 27.55, ['Belarusian']],
  ['RU', 'Russia', 55.75, 37.6, ['Russian', 'Russian Federation', 'Kremlin']],
  ['TR', 'Türkiye', 39.9, 32.85, ['Turkey', 'Turkish', 'Türkiye']],
  ['IL', 'Israel', 31.8, 35.2, ['Israeli']],
  ['PS', 'Palestine', 31.9, 35.2, ['Palestinian', 'Gaza']],
  ['LB', 'Lebanon', 33.9, 35.5, ['Lebanese']],
  ['SY', 'Syria', 33.5, 36.3, ['Syrian']],
  ['IQ', 'Iraq', 33.3, 44.4, ['Iraqi']],
  ['IR', 'Iran', 35.7, 51.4, ['Iranian']],
  ['SA', 'Saudi Arabia', 24.7, 46.7, ['Saudi']],
  ['AE', 'United Arab Emirates', 24.45, 54.4, ['United Arab Emirates', 'Emirati', 'UAE', 'Dubai', 'Abu Dhabi']],
  ['QA', 'Qatar', 25.3, 51.5, ['Qatari']],
  ['KW', 'Kuwait', 29.4, 47.98, ['Kuwaiti']],
  ['BH', 'Bahrain', 26.2, 50.6, ['Bahraini']],
  ['OM', 'Oman', 23.6, 58.4, ['Omani']],
  ['YE', 'Yemen', 15.35, 44.2, ['Yemeni']],
  ['EG', 'Egypt', 30.05, 31.25, ['Egyptian']],
  ['MA', 'Morocco', 34.0, -6.85, ['Moroccan']],
  ['DZ', 'Algeria', 36.75, 3.05, ['Algerian']],
  ['TN', 'Tunisia', 36.8, 10.2, ['Tunisian']],
  ['LY', 'Libya', 32.9, 13.2, ['Libyan']],
  ['NG', 'Nigeria', 9.05, 7.5, ['Nigerian']],
  ['GH', 'Ghana', 5.6, -0.2, ['Ghanaian']],
  ['KE', 'Kenya', -1.3, 36.8, ['Kenyan']],
  ['ET', 'Ethiopia', 9.0, 38.75, ['Ethiopian']],
  ['ZA', 'South Africa', -25.75, 28.2, ['South African']],
  ['SN', 'Senegal', 14.7, -17.45, ['Senegalese']],
  ['CI', "Côte d'Ivoire", 5.35, -4.0, ['Ivory Coast', 'Ivorian']],
  ['AO', 'Angola', -8.85, 13.25, ['Angolan']],
  ['KZ', 'Kazakhstan', 51.15, 71.45, ['Kazakh']],
  ['UZ', 'Uzbekistan', 41.3, 69.25, ['Uzbek']],
  ['AF', 'Afghanistan', 34.55, 69.2, ['Afghan']],
  ['PK', 'Pakistan', 33.7, 73.05, ['Pakistani']],
  ['IN', 'India', 28.6, 77.2, ['Indian']],
  ['BD', 'Bangladesh', 23.8, 90.4, ['Bangladeshi']],
  ['LK', 'Sri Lanka', 6.9, 79.85, ['Sri Lankan']],
  ['NP', 'Nepal', 27.7, 85.3, ['Nepalese', 'Nepali']],
  ['CN', 'China', 39.9, 116.4, ['Chinese', 'PRC', 'Beijing']],
  ['HK', 'Hong Kong', 22.3, 114.2, []],
  ['TW', 'Taiwan', 25.05, 121.55, ['Taiwanese']],
  ['KP', 'North Korea', 39.0, 125.75, ['North Korean', 'DPRK', 'Pyongyang']],
  ['KR', 'South Korea', 37.55, 127.0, ['South Korean', 'Republic of Korea']],
  ['JP', 'Japan', 35.7, 139.7, ['Japanese']],
  ['MN', 'Mongolia', 47.9, 106.9, ['Mongolian']],
  ['VN', 'Vietnam', 21.0, 105.85, ['Vietnamese', 'Viet Nam']],
  ['TH', 'Thailand', 13.75, 100.5, ['Thai']],
  ['MY', 'Malaysia', 3.15, 101.7, ['Malaysian']],
  ['SG', 'Singapore', 1.35, 103.8, ['Singaporean']],
  ['ID', 'Indonesia', -6.2, 106.85, ['Indonesian']],
  ['PH', 'Philippines', 14.6, 121.0, ['Philippine', 'Filipino']],
  ['MM', 'Myanmar', 19.75, 96.1, ['Burmese', 'Burma']],
  ['KH', 'Cambodia', 11.55, 104.9, ['Cambodian']],
  ['AU', 'Australia', -35.3, 149.1, ['Australian']],
  ['NZ', 'New Zealand', -41.3, 174.8, []],
];

// Commonly reported attribution of named actors (public vendor naming).
// Financially-motivated crews without a consistent public attribution are left out.
const ACTOR_ORIGIN = [
  [/\b(bear|apt28|apt29|sandworm|turla|gamaredon|star blizzard|midnight blizzard|forest blizzard|unc2452|nobelium|seashell blizzard)\b/i, 'RU'],
  [/\b(panda|typhoon|apt41|apt27|apt40|apt31|hafnium|blacktech|unc3886|mustang panda)\b/i, 'CN'],
  [/\b(kitten|apt33|apt34|apt35|muddywater|oilrig|charming kitten|sandstorm)\b/i, 'IR'],
  [/\b(chollima|lazarus|apt38|kimsuky|andariel|famous chollima|sleet)\b/i, 'KP'],
  [/\btiger\b/i, 'IN'],
  [/\bbuffalo\b/i, 'VN'],
  [/\bsaiga\b/i, 'KZ'],
];

const BY_CODE = new Map(COUNTRIES.map((c) => [c[0], c]));

// One pass per article: a single case-sensitive alternation (country names and
// demonyms are proper nouns — "polish the report" must not count as Poland),
// longest aliases first so "South Korea" wins over "Korea".
const EXACT = new Map();   // plain alias -> code
const PATTERNS = [];       // [RegExp, code] for aliases written as regex (U.S., U.K.)
const parts = [];
for (const [code, name, , , aliases] of COUNTRIES) {
  for (const a of [name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), ...aliases]) {
    const isPattern = /\\/.test(a.replace(/\\'/g, ''));
    if (isPattern) PATTERNS.push([new RegExp(`^${a}$`), code]);
    else if (!EXACT.has(a)) EXACT.set(a, code);
    parts.push(a);
  }
}
const ALIAS_RE = new RegExp(`(?<![\\w.-])(${[...new Set(parts)].sort((x, y) => y.length - x.length).join('|')})(?![\\w-])`, 'g');
const COUNTRY_FIELD_RE = /\bCountry:\s*([A-Z]{2})\b/;

// code -> the exact text that matched (used as the feed search term)
function matchCountries(text) {
  const found = new Map();
  if (!text) return found;
  for (const m of text.matchAll(ALIAS_RE)) {
    const hit = m[1];
    let code = EXACT.get(hit);
    if (!code) for (const [re, c] of PATTERNS) if (re.test(hit)) { code = c; break; }
    if (code && !found.has(code)) found.set(code, hit);
  }
  return found;
}
function countriesIn(text) { return new Set(matchCountries(text).keys()); }

// code -> first actor attributed to it (doubles as the feed search term)
function originsOf(actors) {
  const out = new Map();
  for (const name of actors) {
    for (const [re, code] of ACTOR_ORIGIN) if (re.test(name)) { if (!out.has(code)) out.set(code, name); break; }
  }
  return out;
}

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * @param {Array<{id,title,description,severity,threat_actors,source_type}>} articles
 */
function buildGeo(articles, days) {
  const countries = new Map();
  const arcs = new Map();
  let geolocated = 0;

  const bump = (code, a, role, term) => {
    const meta = BY_CODE.get(code);
    if (!meta) return;
    let c = countries.get(code);
    if (!c) {
      c = { code, name: meta[1], lat: meta[2], lon: meta[3], count: 0, critical: 0, high: 0, ransomware: 0, origin: 0, worst: 'low', top: [], terms: new Map() };
      countries.set(code, c);
    }
    c.count++;
    if (term) c.terms.set(term, (c.terms.get(term) || 0) + 1);
    if (role === 'origin') c.origin++;
    if (a.severity === 'critical') c.critical++;
    if (a.severity === 'high') c.high++;
    if ((SEV_RANK[a.severity] || 0) > (SEV_RANK[c.worst] || 0)) c.worst = a.severity;
    if (/Ransomware Leak/i.test(a.title || '')) c.ransomware++;
    if (c.top.length < 3) c.top.push({ id: a.id, title: String(a.title || '').slice(0, 140), severity: a.severity || 'low' });
  };

  for (const a of articles) {
    const text = `${a.title || ''}\n${a.description || ''}`;
    const named = matchCountries(text);
    const field = COUNTRY_FIELD_RE.exec(a.description || '');
    if (field && BY_CODE.has(field[1])) named.set(field[1], `Country: ${field[1]}`);

    const actors = String(a.threat_actors || '').split(',').map((s) => s.trim()).filter(Boolean);
    const origins = originsOf(actors);

    if (!named.size && !origins.size) continue;
    geolocated++;
    for (const [code, term] of named) bump(code, a, origins.has(code) ? 'origin' : 'target', term);
    for (const [code, actor] of origins) if (!named.has(code)) bump(code, a, 'origin', actor);

    for (const from of origins.keys()) {
      for (const to of named.keys()) {
        if (to === from) continue;
        const key = `${from}>${to}`;
        let arc = arcs.get(key);
        if (!arc) {
          arc = { from, to, fromName: BY_CODE.get(from)[1], toName: BY_CODE.get(to)[1], count: 0, worst: 'low', actors: new Set() };
          arcs.set(key, arc);
        }
        arc.count++;
        actors.forEach((x) => arc.actors.add(x));
        if ((SEV_RANK[a.severity] || 0) > (SEV_RANK[arc.worst] || 0)) arc.worst = a.severity;
      }
    }
  }

  const list = [...countries.values()]
    .sort((x, y) => y.count - x.count || y.critical - x.critical)
    .slice(0, 80)
    .map(({ terms, ...c }) => ({ ...c, term: [...terms.entries()].sort((x, y) => y[1] - x[1])[0]?.[0] || c.name }));
  const arcList = [...arcs.values()]
    .sort((x, y) => y.count - x.count)
    .slice(0, 40)
    .map((x) => ({ ...x, actors: [...x.actors].slice(0, 4) }));

  return {
    days,
    totalArticles: articles.length,
    geolocated,
    countries: list,
    arcs: arcList,
    generatedAt: new Date().toISOString(),
  };
}

module.exports = { buildGeo, countriesIn, matchCountries, originsOf, COUNTRIES };
