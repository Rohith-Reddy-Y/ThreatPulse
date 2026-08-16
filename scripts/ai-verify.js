// Temporary AI verification script — exercises the real client + websearch against live APIs.
require('dotenv').config();
const ai = require('../src/ai/client');
const websearch = require('../src/ai/websearch');
const prompts = require('../src/ai/prompts');

const sampleArticle = {
  title: 'Critical RCE vulnerability found in Apache Log4j',
  source_name: 'TestSource',
  severity: 'critical',
  category: 'vulnerability',
  description: 'Security researchers discovered a remote code execution flaw (CVE-2021-44228) affecting Apache Log4j versions 2.0 to 2.14.1. The vulnerability allows unauthenticated attackers to execute arbitrary code. A proof-of-concept exploit is publicly available.'
};

(async () => {
  console.log('=== status ===', 'enabled:', ai.isEnabled(), 'model:', ai.MODEL);

  console.log('\n=== TEST 1: summary (json default) ===');
  const sum = await ai.generate(prompts.summaryPrompt(sampleArticle), sampleArticle.title);
  console.log('ok:', sum.ok, '| parsed keys:', Object.keys(ai.parseJson(sum.text) || {}));

  console.log('\n=== TEST 2: triage (json default) ===');
  const tri = await ai.generate(prompts.triagePrompt(sampleArticle), sampleArticle.title);
  console.log('ok:', tri.ok, '| parsed:', JSON.stringify(ai.parseJson(tri.text)));

  console.log('\n=== TEST 3: web-QA now with json:false (must be PLAIN TEXT, not JSON) ===');
  const results = await websearch.search('MOVEit breach latest', 3);
  const context = results.map((r, i) => `[${i + 1}] ${r.title}\nURL: ${r.url}\n${r.snippet}`).join('\n\n');
  const web = await ai.generate(prompts.webQaPrompt('What is the latest on the MOVEit breach?', context), 'What is the latest on the MOVEit breach?', { temperature: 0.4, json: false });
  console.log('ok:', web.ok);
  if (web.ok) {
    const t = web.text || '';
    const looksLikeJson = t.trim().startsWith('{') && t.trim().endsWith('}');
    console.log('looksLikeJson (should be false):', looksLikeJson);
    console.log('answer preview:', JSON.stringify(t.slice(0, 350)));
  } else {
    console.log('error:', web.error);
  }

  console.log('\n=== TEST 4: websearch results ===');
  console.log('hasTavily:', websearch.hasTavily(), 'results:', results.length);

  process.exit(0);
})().catch(e => { console.error('FATAL', e); process.exit(1); });
