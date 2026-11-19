'use strict';
// Optional DOM-free runtime test. Uses built-in Node APIs only, never the network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '..', 'access', 'dashboard.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert(script, 'inline JavaScript present');

class Element {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.handlers = {};
    this._text = '';
    this.value = '';
    this.disabled = false;
    this.className = '';
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(x => x.textContent).join(''); }
  append(...values) { this.children.push(...values); }
  replaceChildren(...values) { this._text = ''; this.children = [...values]; }
  addEventListener(kind, handler) { this.handlers[kind] = handler; }
  // Prevent accidentally switching to unsafe HTML interpolation in future revisions.
  set innerHTML(_) { throw new Error('Unsafe DOM write detected'); }
}
const ids = new Map();
const document = {
  getElementById(id) { if (!ids.has(id)) ids.set(id, new Element(id)); return ids.get(id); },
  createElement(tag) { return new Element(tag); },
};
const id = key => document.getElementById(key);
const signals = [
  {kind:'wazuh_rule_repeated_15m',source:'wazuh_indexer',count:5,window_minutes:15},
  {kind:'wazuh_multiple_rules_observed_15m',source:'wazuh_indexer',minimum_distinct_rules:3,window_minutes:15},
  {kind:'prometheus_scrape_unavailable',source:'prometheus',observation:'up_equals_zero'},
  {kind:'loki_ssh_service_log_volume_increase',source:'loki_timeline',bucket_minutes:5,window_counts:[1,2,6],anchor_type:'event_time'},
];
const base = {version:'cross-source-patterns-v1',status:'ok',changes_triage:false,changes_notifications:false};
const temporal = {
 version:'wazuh-received-sequence-v1',status:'ok',
 source:'authenticated_wazuh_webhooks_received_by_bot',
 scope:'same_verified_wazuh_agent_and_host',
 time_basis:'bot_reception_time_not_original_event_time', window_minutes:30,
 previous_verified_incidents:2, prior_same_rule:1,
 distinct_rule_count_including_current:2, truncated:false,
 changes_triage:false,changes_notifications:false,sent_to_ai:false,raw_logs_stored:false,
 observations:['different_wazuh_rules_received_30m','at_least_3_webhooks_received_5m'],
 timeline:[
  {incident_id:3,rule_id:'5760',age_seconds:240},
  {incident_id:5,rule_id:'5763',age_seconds:120},
  {incident_id:null,rule_id:'5763',age_seconds:0}
 ]
};
const incident = (id,source,extra = {}) => ({
  id, source, received_at:'2026-11-12T11:00:00Z', title:'Evento '+id,
  severity:'12', synthetic:false, mode:'rules_only',
  analysis:{summary:'Análisis',priority:'high',...extra},
});
const records = [
 incident(6,'wazuh',{cross_source_patterns:{...base,signal_count:4,signals,sources_validated:['wazuh_webhook','wazuh_indexer','prometheus','loki_timeline']},temporal_sequence:temporal}),
 incident(5,'wazuh',{cross_source_patterns:{...base,signal_count:0,signals:[],sources_validated:['wazuh_webhook']}}),
 incident(4,'wazuh',{}),
 incident(3,'grafana',{}),
 incident(2,'wazuh',{cross_source_patterns:{...base,signal_count:2,signals:[],sources_validated:['wazuh_webhook']}}),
 incident(1,'wazuh',{cross_source_patterns:{...base,status:'insufficient_data'}}),
];
const groupBase = {
 version:'bot-incident-groups-v1',status:'grouped',
 scope:'last_50_incidents_received_by_bot',time_basis:'bot_reception_time',
 window_minutes:30,group_id:'wazuh-window-5',member_count:2,
 member_ids:[5,6],distinct_rule_count:2,rule_ids:['5760','5763'],
 max_rule_level:15,max_priority:'critical',observations:['multiple_rules'],
 limited_history:true,changes_triage:false,changes_notifications:false,
 sent_to_ai:false,automatic_actions:false
};
records[0].incident_group={...groupBase};
records[1].incident_group={...groupBase};
records[4].incident_group={...groupBase,group_id:'<img src=x onerror=alert(1)>'};
const evolutionBase={
 version:'bot-group-evolution-v1',status:'observed',
 scope:'last_50_incidents_received_by_bot',time_basis:'bot_reception_time',
 window_minutes:30,group_id:'wazuh-window-5',member_count:2,
 first_rule_level:10,latest_rule_level:15,max_rule_level:15,
 peak_increased_after_first:true,introduced_rule_ids:['5760'],
 review_priority:'critical',priority_source:'max_verified_wazuh_rule_level',
 review_indicators:['later_higher_rule_level','new_rule_ids'],
 limited_history:true,changes_triage:false,changes_notifications:false,
 sent_to_ai:false,automatic_actions:false
};
records[0].group_evolution={...evolutionBase};
records[1].group_evolution={...evolutionBase};
records[4].group_evolution={...evolutionBase,review_priority:'<img src=x onerror=alert(1)>'};
let interval = null;
const context = {
  document,
  fetch:async (url,opts) => {
    assert.equal(url,'/api/incidents');
    assert.equal(opts.credentials,'same-origin');
    assert.equal(opts.headers,undefined);
    return {ok:true,status:200,json:async()=>records};
  },
  setInterval:fn=>{interval=fn;return 123;},clearInterval:()=>{interval=null;},
  Date, Set,
};
(async()=>{
  vm.runInNewContext(script,context,{filename:'dashboard-inline.js',timeout:500});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(id('total').textContent,'6');
  assert.equal(id('correlated').textContent,'2');
  assert.equal(id('patterned').textContent,'1');
  assert.equal(id('groupsCount').textContent,'1');
  assert.equal(id('groupedCount').textContent,'2');
  assert.equal(id('risingGroups').textContent,'1');
  assert.equal(id('introducedGroups').textContent,'1');
  assert.equal(id('groupList').children.length,1);
  assert(id('groupList').textContent.includes('wazuh-window-5'));
  assert(!id('groupList').textContent.includes('<img'));
  id('groupFilter').value='grouped';id('groupFilter').handlers.change();
  assert.equal(id('rows').children.length,2);
  id('groupFilter').value='';id('groupFilter').handlers.change();
  id('groupList').children[0].handlers.click();
  assert(id('detail').textContent.includes('Agrupación de incidentes'));
  assert(id('detail').textContent.includes('nivel máximo Wazuh 15'));
  assert(id('detail').textContent.includes('Evolución del grupo'));
  assert(id('detail').textContent.includes('primero 10'));
  assert(id('detail').textContent.includes('último 15'));
  assert(id('detail').textContent.includes('Reglas adicionales observadas: 5760'));
  assert(id('groupList').textContent.includes('subida de nivel observada'));
  id('evolutionFilter').value='rise';id('evolutionFilter').handlers.change();
  assert.equal(id('rows').children.length,2);
  id('evolutionFilter').value='new_rules';id('evolutionFilter').handlers.change();
  assert.equal(id('rows').children.length,2);
  id('evolutionFilter').value='';id('evolutionFilter').handlers.change();

  assert.equal(id('rows').children.length,6);
  assert(id('detail').textContent.includes('Regla Wazuh repetida'));
  assert(id('detail').textContent.includes('fallo de scrape'));
  assert(id('detail').textContent.includes('no prueban causalidad'));
  assert(id('detail').textContent.includes('Secuencia temporal de Wazuh'));
  assert(id('detail').textContent.includes('Regla 5760'));
  assert(id('detail').textContent.includes('Incidente #3'));
  assert(id('detail').textContent.includes('Orden por recepción del bot'));
  id('correlation').value='signals';id('correlation').handlers.change();
  assert.equal(id('rows').children.length,1);
  id('correlation').value='not_recorded';id('correlation').handlers.change();
  assert.equal(id('rows').children.length,1);
  id('rows').children[0].handlers.click();
  assert(id('detail').textContent.includes('No calculada'));
  id('correlation').value='insufficient_data';id('correlation').handlers.change();
  assert.equal(id('rows').children.length,1);
  id('correlation').value='';id('correlation').handlers.change();
  id('rows').children.find(el=>el.textContent.includes('#2')).handlers.click();
  assert(id('detail').textContent.includes('no verificables'));
  assert.equal(typeof interval,'function');
  console.log('OK: authenticated bridge correlations, filters, strict data validation, safe DOM');
})().catch(e=>{ console.error(e);process.exitCode=1; });
