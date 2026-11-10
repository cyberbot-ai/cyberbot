<script setup lang="ts">
import ServerTabBar from './ServerTabBar.vue';
import MetricValue from './MetricValue.vue';
import RelativeDate from './RelativeDate.vue';
import { formatTimeRange } from '../dateTime';
import { computed,ref,watch,onUnmounted } from 'vue';
import {call,preview} from '../api';
import type {LogView} from '../types';
const props=defineProps<{serverId:string;now:number}>();const emit=defineEmits<{updated:[]}>();
const view=ref<LogView>();const error=ref('');const busy=ref(false);
const labels:Record<string,string>={ssh_failed:'Failed logins',ssh_accepted:'Successful logins',ssh_noise:'Other SSH activity',ssh_banned:'Fail2ban bans',ssh_blocked:'Firewall blocks',ssh_failures_mitigated:'Attempts from blocked addresses',system_error:'System errors',oom:'Out-of-memory events',disk_io:'Disk errors',service_crash:'Service failures',protection_failure:'Fail2ban errors',ssh_suspicious_success:'Suspicious successful logins'};
const fail2banReasons = new Map([
  ['Fail2ban log source missing', 'Fail2ban could not find its log during a check.'],
  ['Fail2ban startup failed', 'Fail2ban or one of its jails failed to start.'],
  ['Fail2ban blocking action failed', 'Fail2ban could not apply or remove a ban.'],
]);
const gaps:Record<string,string>={backlog_skipped:'Older entries skipped. Recent entries were read.',clock_changed:'Clock changed or drifted',unknown_timestamp:'Unrecognized timestamp',dedupe_limit:'Deduplication limit reached',pattern_limit:'Log pattern limit reached',rotation_tail_lost:'End of rotated log unavailable',source_unavailable:'Log source unavailable',file_rewritten:'File rewritten',file_truncated:'File truncated',long_line:'Line too long',incomplete_line:'Incomplete line',invalid_encoding:'Unknown encoding',read_limit:'Read or time limit reached',journal_error:'Journal error',journal_reboot:'System rebooted',journal_message_unavailable:'Journal entry has no readable message',journal_format:'Unknown journal format',journal_cursor_lost:'Journal cursor unavailable',source_changed:'Log source changed',output_limit:'Summary truncated'};
const counts=computed(()=>Object.entries(view.value?.summary?.counts??{}));
const ssh=computed(()=>counts.value.filter(([k])=>k.startsWith('ssh_')));
const events=computed(()=>counts.value.filter(([k])=>!k.startsWith('ssh_')));
const protectionReasons = computed(() => [...new Set((view.value?.summary?.examples ?? [])
  .filter(example => example.category === 'protection_failure')
  .map(example => fail2banReasons.get(example.template))
  .filter(Boolean))]);
const events1 = (n: number) => n === 1 ? 'event' : 'events';
const outcome = computed(() => {
  const current = view.value;
  if (!current?.summary) return null;
  const findings = current.summary.findings;
  if (current.severity || findings.length) {
    const critical = current.severity === 'critical' || findings.some(f => f.severity === 'critical');
    return { label: 'Findings detected', tone: critical ? 'crit' : 'warn' };
  }
  if (current.error) return { label: 'Log check failed', tone: '' };
  if (current.monitoring?.enabled === false) return null;
  if (!current.fresh) return { label: 'Data is stale', tone: '' };
  if (!current.summary.coverage.sources.length) return { label: 'No log sources available', tone: '' };
  return { label: 'No issues found', tone: 'ok' };
});
let version=0;
async function load(){const id=props.serverId;const v=++version;try{const result=await call<LogView>('log_summary',{id});if(v===version)view.value=result;}catch(e){if(v===version)error.value=String(e);}}
watch(()=>props.serverId,()=>{view.value=undefined;error.value='';void load();},{immediate:true});
watch(()=>props.now,()=>{if(!document.hidden&&!busy.value)void load();});onUnmounted(()=>{version++;});
async function refresh(){busy.value=true;error.value='';try{await call('diagnose',{id:props.serverId,kind:'logs'});await load();emit('updated');}catch(e){error.value=String(e);await load();}finally{busy.value=false;}}
</script>
<template>
<section class="logs">
<ServerTabBar title="System and SSH logs" :busy="busy" :disabled="preview || view?.monitoring?.enabled===false" @refresh="refresh">
  <span v-if="outcome" class="tag" :class="outcome.tone">{{ outcome.label }}</span>
  <RelativeDate :at="view?.lastSuccess" empty="Not checked yet"/>
</ServerTabBar>
<p v-if="view?.monitoring?.enabled===false" class="notice">Monitoring is off. You can enable it in the Monitoring library.</p><p v-if="error||view?.error" class="problem" role="alert">{{error||view?.error}}</p>
<p v-if="!view?.summary" class="note">Results will appear after the next scheduled check.</p>
<template v-if="view?.summary">
<section v-if="view.summary.findings.length || view.severity" class="block">
  <h4>Findings</h4>
  <div v-for="f in view.summary.findings" :key="f.check" class="finding-item">
    <div class="finding"><span class="tag" :class="f.severity==='critical'?'crit':'warn'">{{f.severity==='critical'?'Critical':'Needs attention'}}</span><strong>{{f.check==='logs:protection_failure'?'Fail2ban error':f.title}}</strong><span class="count">{{f.count}} {{events1(f.count)}}</span></div>
    <div v-if="view.findingExamples?.[f.check]" class="log-example">
      <div class="example-meta">Log example · {{view.findingExamples[f.check].source}} · <RelativeDate :at="view.findingExamples[f.check].at"/></div>
      <code>{{view.findingExamples[f.check].text}}</code>
    </div>
    <p v-else class="hint">No log example was saved for this finding.</p>
    <template v-if="f.check==='logs:protection_failure'">
      <p v-for="reason in protectionReasons" :key="reason" class="hint">{{reason}}</p>
      <p v-if="!protectionReasons.length && !view.findingExamples?.[f.check]" class="hint">Fail2ban recorded an error. The summary doesn’t contain the exact cause.</p>
      <p class="hint">Check status with <code>fail2ban-client status</code>. Look up the event in <code>/var/log/fail2ban.log</code> or run <code>journalctl -u fail2ban</code>.</p>
    </template>
  </div>
  <p v-if="!view.summary.findings.length" class="note">Awaiting confirmation of recovery. See the Incidents tab for details.</p>
</section>
<div class="columns">
<section v-if="events.length" class="block"><h4>System events</h4><dl><template v-for="[k,n] in events" :key="k"><dt>{{labels[k]??k}}</dt><dd><MetricValue :value="n" :precision="0"/></dd></template></dl></section>
<section class="block"><h4>SSH activity and protection</h4><dl v-if="ssh.length"><template v-for="[k,n] in ssh" :key="k"><dt>{{labels[k]??k}}</dt><dd><MetricValue :value="n" :precision="0"/></dd></template></dl><p class="hint">Failed logins and bans alone do not trigger incidents or AI investigations. {{(view.summary.counts.ssh_banned||view.summary.counts.ssh_blocked)?'Blocks were recorded.':'The available logs show no blocks in this period.'}}</p></section>
</div>
<details v-if="view.summary.examples.length"><summary>Redacted examples: {{view.summary.examples.length}}</summary><article v-for="(e,i) in view.summary.examples" :key="i"><strong>{{labels[e.category]}}</strong> · <RelativeDate :at="e.at"/><p v-if="e.category==='protection_failure' && fail2banReasons.has(e.template)">{{fail2banReasons.get(e.template)}}</p><p v-if="e.peer">Address {{e.peer}} · account {{e.account}}</p></article></details>
<details class="quality"><summary>Log coverage</summary><ul>
<li>Period · {{ formatTimeRange(view.summary.remoteAt - view.summary.windowSeconds, view.summary.remoteAt) }}</li>
<li>Log sources: {{view.summary.coverage.sources.join(', ')||'none available'}}. {{view.summary.learning?'Cyberbot is learning normal activity and checks for known errors immediately.':'Cyberbot compares activity with its baseline.'}}</li>
<li v-if="view.summary.coverage.initial">At the first check, only recent records are read.</li>
<li v-if="view.summary.windowSeconds === 0">Both checks ran in the same second.</li>
<li v-if="view.summary.sshCorrelationLimited">Some failed attempts could not be correlated with successful logins because there were too many source addresses.</li>
<li v-for="(g,i) in view.summary.coverage.gaps" :key="i">{{g.source}}: {{gaps[g.reason]??g.reason}}<small v-if="g.fromOffset!=null"> · bytes {{g.fromOffset}}–{{g.toOffset}}</small><small v-if="g.fromTime!=null"> · <RelativeDate :at="g.fromTime"/> – <RelativeDate :at="g.toTime??g.fromTime"/></small></li>
<li>Logs are analyzed on the server without AI. The desktop app shows short excerpts for findings and redacted examples for selected events.</li>
<li><small>Received {{view.summary.bytesReceived}} bytes · read {{view.summary.bytesRead}} bytes on the server · {{view.summary.durationMs}} ms. Figures exclude SSH overhead.</small></li></ul></details>
<details v-if="view.lastIncomplete" class="quality">
  <summary>Previous gaps · {{ formatTimeRange(view.lastIncomplete.remoteAt - view.lastIncomplete.windowSeconds, view.lastIncomplete.remoteAt) }}</summary>
  <ul>
    <li v-for="(gap, i) in view.lastIncomplete.gaps" :key="i">
      {{ gap.source }} · {{ gaps[gap.reason] ?? gap.reason }}
      <small v-if="gap.fromTime != null"> · {{ formatTimeRange(gap.fromTime, gap.toTime ?? gap.fromTime) }}</small>
    </li>
  </ul>
</details>
</template></section>
</template>
<style scoped>
.logs{border:0;margin:0;padding:0}h4{font-size:13px;font-weight:600;margin:0 0 8px}.tag{display:inline-flex;align-items:center;padding:1px 9px;border-radius:20px;background:var(--subtle);color:var(--muted);white-space:nowrap;font-size:12px}.tag.ok{background:var(--accent-bg);color:var(--success)}.tag.warn{background:var(--warning-bg);color:var(--warning)}.tag.crit{background:var(--danger-bg);color:var(--danger)}
p,li{font-size:13px;line-height:1.6;color:var(--muted);overflow-wrap:anywhere}p{max-width:75ch}.note{margin:0}.hint{font-size:12px;margin:8px 0 0}button{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer;white-space:nowrap}button:hover:enabled{background:var(--hover)}button:disabled{opacity:.45;cursor:default}.problem{padding:10px 12px;background:var(--danger-bg);color:var(--danger);border-radius:7px;margin:0 0 12px}
.block{margin-bottom:22px}.finding-item{padding:9px 0;border-bottom:1px solid var(--line)}.finding{display:flex;align-items:center;gap:10px;font-size:13px}.finding strong{flex:1;min-width:0;font-weight:500;overflow-wrap:anywhere}.finding .count{color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.log-example{min-width:0;margin-top:8px;padding:8px 10px;background:var(--subtle);border-radius:7px;overflow-wrap:anywhere}.example-meta{color:var(--muted);font-size:12px}.log-example code{display:block;margin-top:4px;color:var(--text);font-size:12px;line-height:1.5;white-space:pre-wrap}
.columns{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:28px}dl{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px 16px;font-size:13px;margin:0}dt{min-width:0;overflow-wrap:anywhere;color:var(--muted)}dd{margin:0;text-align:right}
details{margin:8px 0;font-size:13px;color:var(--muted)}summary{cursor:pointer}.quality{background:var(--subtle);border-radius:10px;padding:10px 14px}.quality ul{margin:8px 0 2px;padding-left:18px}article{padding:10px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}small{font-size:12px;color:var(--muted)}
button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
@media(max-width:650px){.columns{grid-template-columns:1fr;gap:0}}
</style>
