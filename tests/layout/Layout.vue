<script setup lang="ts">
import { computed,ref } from 'vue';
import { scenario,value } from './api';
import ServerRibbon from '../../src/components/ServerRibbon.vue';
import ServerCard from '../../src/components/ServerCard.vue';
import ServerDetail from '../../src/components/ServerDetail.vue';
import ServicePanel from '../../src/components/ServicePanel.vue';
import NginxPanel from '../../src/components/NginxPanel.vue';
import PostgresqlPanel from '../../src/components/PostgresqlPanel.vue';
import LogPanel from '../../src/components/LogPanel.vue';
import DependenciesPanel from '../../src/components/DependenciesPanel.vue';
import type { Server } from '../../src/types';
const width=ref(1200),dark=ref(false),longNames=ref(false),panel=ref('dashboard');
const now=Date.now()/1000;
const kinds=['mysql','redis','mongodb','docker','php-fpm','asterisk','clickhouse','cockroach'];
const server=computed<Server>(()=>({id:scenario.value,sourceId:'fixture',name:longNames.value?'server-with-a-very-long-name-'.repeat(6):'s3.db.srv.game.hrum.me',endpoint:{host:'127.0.0.1',user:'ops',port:22,identityFile:null,jumpHost:null},observation:{at:now,cpuPercent:1,memoryPercent:scenario.value==='maximum'?value():40,load:value(),swapPercent:0,uptime:10,disks:[{mount:longNames.value?'/data/'+('very-long-path/'.repeat(10)):'/',usedPercent:40,inodePercent:3}],services:[{name:'sshd.service',state:'active'}],missing:[],bytesReceived:1024,durationMs:20},nginx:{detected:true,status:'healthy',rps:value(),rpsSource:'access_log',at:now},services:[{kind:'redis',instanceId:'cache',name:longNames.value?'Redis · '+('very-long-instance-name-'.repeat(6)):'Redis · Cache',status:'healthy',at:now}],lastError:null,lastAttempt:now,nextCheck:now+180,failures:0}));
</script>
<template>
<main class="harness" :class="{dark}">
  <header><h1>Size of indicators</h1><p>Local fixtures · SSH and AI are not available</p><div class="controls">
    <label>Data data<select v-model="scenario"><option value="normal">Normal</option><option value="large">LA from a screenshot</option><option value="maximum">Maximum numbers</option></select></label>
    <label>Width<select v-model.number="width"><option v-for="w in [320,480,768,1200]" :key="w" :value="w">{{w}}</option></select></label>
    <label>Screen<select v-model="panel"><option value="dashboard">dashboard</option><option value="detail">Server</option><option value="dependencies">Server connections</option><option value="nginx">Nginx</option><option value="postgresql">PostgreSQL</option><option value="logs">Logs</option><option v-for="kind in kinds" :key="kind" :value="kind">{{kind}}</option></select></label>
    <label><input v-model="longNames" type="checkbox">Long names</label><label><input v-model="dark" type="checkbox">Dark theme</label>
  </div></header>
  <div class="surface app" :style="{width:width+'px'}" :data-scenario="scenario" :data-panel="panel">
    <template v-if="panel==='dashboard'"><h2>Ribbon</h2><ServerRibbon :server="server" :now="now" :interval="180"/><ServerRibbon :server="server" :now="now" :interval="180" alternate/>
      <h2>Card</h2><div class="cards"><ServerCard :server="server" :now="now" :interval="180"/><ServerCard :server="server" :now="now" :interval="180"/></div>
    </template>
    <ServerDetail v-else-if="panel==='detail'" :key="scenario" :server="server" :now="now" :interval="180"/>
    <DependenciesPanel v-else-if="panel==='dependencies'" :key="scenario" :server-id="server.id"/>
    <NginxPanel v-else-if="panel==='nginx'" :key="scenario" :server-id="server.id" :now="now"/>
    <PostgresqlPanel v-else-if="panel==='postgresql'" :key="scenario" :server-id="server.id" :now="now"/>
    <LogPanel v-else-if="panel==='logs'" :key="scenario" :server-id="server.id" :now="now"/>
    <ServicePanel v-else :key="panel+scenario" :server-id="server.id" :kind="panel" :now="now"/>
  </div>
</main>
</template>
<style scoped>
.harness{--canvas:#f7f8f5;--surface:#fff;--subtle:#f0f2ee;--hover:#e9ede7;--line:#d9ded5;--line-strong:#b2bcb0;--text:#242a25;--muted:#626c61;--accent:#355c40;--accent-bg:#e2ecdf;--success:#287347;--warning:#8d5b13;--warning-bg:#faf0dc;--danger:#b03d37;--danger-bg:#fae8e5;color:var(--text);background:var(--canvas);padding:12px;min-height:100vh;box-sizing:border-box;font:13px/1.5 -apple-system,BlinkMacSystemFont,sans-serif}
.dark{--canvas:#191c1b;--surface:#202422;--subtle:#262b28;--hover:#2d332f;--line:#353c36;--line-strong:#59665c;--text:#e8ede6;--muted:#a0aca1;--accent:#b5d2aa;--accent-bg:#2e3f30;--success:#97c9a2;--warning:#e2bc77;--warning-bg:#3b3324;--danger:#eda39a;--danger-bg:#402b28;color-scheme:dark}
header{margin-bottom:20px}h1{font-size:20px;margin:0}h2{font-size:13px;margin:20px 0 10px}p{margin:6px 0;color:var(--muted)}.controls{display:flex;gap:12px;align-items:end;flex-wrap:wrap}label{display:flex;gap:5px;align-items:center;flex-wrap:wrap}select{font:inherit;padding:6px;background:var(--surface);color:var(--text);border:1px solid var(--line);border-radius:5px}.surface{box-sizing:border-box;padding:12px;max-width:100%;background:var(--surface);border:1px solid var(--line)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(250px,100%),1fr));gap:12px}
</style>
