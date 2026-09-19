#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1></header><div class=wrap>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1>Blocking active</b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30>30s</option><option value=300 selected>5 min</option><option value=1800>30 min</option><option value=0>until I re-enable</option></select>
<button id=pausebtn onclick=togglePause()>Pause</button></div>
<div class=cards id=sys></div>
<h2>CLIENTS</h2><table id=ct><thead><tr><th>Client</th><th>MAC</th><th>Blocked</th><th>Allowed</th><th></th></tr></thead><tbody></tbody></table>
<h2>CUSTOM BLOCKED DOMAINS</h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom()>Block domain</button></div>
<table id=cl><tbody></tbody></table>
<h2>MANUAL ALLOWLIST</h2>
<div style=margin-bottom:8px><input id=allowdom placeholder="example.com" size=30><button onclick=addAllowDom()>Allow exact domain</button> <span id=allowmsg style=color:#8b949e></span></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:8px">Exact normalized match only: case, one leading <code>www.</code>, and one terminal dot normalize away. <code>example.com</code> does not allow <code>foo.example.com</code>.</div>
<table id=al><tbody></tbody></table>
<h2>UPSTREAM DNS</h2>
<form id=upstreamForm style=margin-bottom:6px><input id=upstreamInput size=16 maxlength=15 inputmode=decimal placeholder="9.9.9.9"><button>Save</button> <span id=upstreamMsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">Exact IPv4 address only; DNS uses port 53. Hostnames, URLs, ports, loopback, multicast, broadcast, and this device's current address are rejected. A DHCP reservation is recommended for the router or resolver.</div>
)HTML"
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
R"HTML(<h2>NETWORK ADDRESS</h2>
<div id=networkState style="padding:10px;background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:8px">Loading network state...</div>
<form id=networkForm style="margin-bottom:6px">
<div style=margin-bottom:6px><label style="display:block;color:#8b949e;font-size:12px;margin-bottom:2px">Mode</label><select id=networkMode><option value=dhcp>DHCP (default)</option><option value=static>Static IPv4</option></select></div>
<div style=margin-bottom:6px><label style="display:block;color:#8b949e;font-size:12px;margin-bottom:2px">IP address</label><input id=networkIp placeholder="IP address" value="192.168.5.5" size=14></div>
<div style=margin-bottom:6px><label style="display:block;color:#8b949e;font-size:12px;margin-bottom:2px">Netmask</label><input id=networkMask placeholder="Netmask" value="255.255.255.0" size=16></div>
<div style=margin-bottom:6px><label style="display:block;color:#8b949e;font-size:12px;margin-bottom:2px">Gateway (puerta de enlace)</label><input id=networkGateway placeholder="Gateway" value="192.168.5.1" size=14></div>
<div style=margin-bottom:6px><label style="display:block;color:#8b949e;font-size:12px;margin-bottom:2px">Resolver DNS</label><input id=networkDns placeholder="Resolver DNS" value="1.1.1.1" size=14></div>
<button>Start 180s trial</button> <span id=networkMsg style=color:#8b949e></span>
</form><button id=networkConfirm style="display:none">Confirm this new address</button>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">A network change disconnects this page. Reconnect at the new URL shown above and explicitly confirm within 180 seconds. The server owns the countdown; an old tab or Host header cannot confirm a different trial.</div>
<h2>RESET</h2>
<div style="color:#8b949e;font-size:12px;margin-bottom:8px">Connection reset clears WiFi and network address settings only, then reboots into the setup portal; upstream DNS, allowlist, bans, blocklist, and update settings are kept. Factory reset also clears upstream DNS, the manual allowlist, client bans, and update settings, restoring DHCP + Quad9 + blocking-on defaults after reboot; firmware and the blocklist itself are never touched. Both are rejected while a blocklist or firmware update is in progress.</div>
<div style=margin-bottom:18px>
<button id=resetConnectionBtn style="border-color:#f0883e;color:#f0883e">Connection reset</button>
<button id=resetFactoryBtn style="border-color:#f85149;color:#f85149">Factory reset</button>
<span id=resetMsg style=color:#8b949e></span>
</div>
)HTML"
#endif
R"HTML(<h2>BLOCKLIST &mdash; UPLOAD</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button>Upload blocklist</button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code>, then upload here &mdash; no USB</div>
<h2>BLOCKLIST &mdash; REMOTE AUTO-UPDATE</h2>
<div style=margin-bottom:6px><input id=uurl placeholder="https://host/blocklist.bin" size=40> every <input id=uiv size=2 value=24>h
<button onclick=saveUpd()>Save</button> <button onclick=fetchNow()>Fetch now</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">device pulls a prebuilt <code>blocklist.bin</code> on a schedule (e.g. a GitHub release asset). last: <span id=ustat>&mdash;</span></div>
<h2>FIRMWARE &mdash; OTA UPDATE</h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button>Flash firmware</button> <span id=fwmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">upload <code>.pio/build/c3/firmware.bin</code> &mdash; device verifies it and reboots into it</div>
</div><script>
function fmt(n){return n.toLocaleString()}
function togglePause(){if(blockstate.dataset.on=='1')fetch('/pause?s='+pausedur.value).then(load);else fetch('/resume').then(load);}
async function load(){try{let r=await fetch('/stats.json');if(!r.ok)throw Error(await r.text());let s=await r.json();
host.textContent='@ '+s.ip;
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?'Blocking active':(s.resumeIn>0?'Paused — resumes in '+s.resumeIn+'s':'Paused');
pausebtn.textContent=on?'Pause':'Resume';pausedur.style.display=on?'':'none';
sys.innerHTML=[['Total blocked',fmt(s.blocked),'b'],['Total allowed',fmt(s.allowed),'a'],['Blocklist',fmt(s.domains)+' domains',''],
['Clients',s.clients.length,''],['WiFi',s.rssi+' dBm',''],['Temp',s.temp+' °C',''],['Free RAM',Math.round(s.heap/1024)+' KB',''],['Uptime',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>BANNED</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban onclick="fetch('/ban?ip=${c.ip}').then(load)">${c.banned?'Unban':'Ban'}</button></td></tr>`).join('');
renderDomainTable(cl,s.custom,'/unblock?d=');
renderDomainTable(al,s.allow,'/unallow?d=');
if(document.activeElement!=upstreamInput)upstreamInput.value=s.upstream||'9.9.9.9';
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=s.upstat||'—';}catch(e){allowmsg.textContent='✗ dashboard fetch failed';}}
function renderDomainTable(table,values,endpoint){let body=table.tBodies[0];body.textContent='';if(!values.length){let row=document.createElement('tr'),cell=document.createElement('td');cell.textContent='none yet';cell.style.color='#8b949e';row.appendChild(cell);body.appendChild(row);return;}values.forEach(d=>{let row=document.createElement('tr'),cell=document.createElement('td');cell.textContent=d;row.appendChild(cell);let action=document.createElement('td');action.style.textAlign='right';let button=document.createElement('button');button.textContent='remove';button.onclick=()=>domainRequest(endpoint,d);action.appendChild(button);row.appendChild(action);body.appendChild(row);});}
async function domainRequest(endpoint,value){let msg=allowmsg;msg.textContent='saving...';try{let r=await fetch(endpoint+encodeURIComponent(value));let t=await r.text();msg.textContent=r.ok?'✓ '+t:'✗ '+t;if(r.ok)await load();}catch(_){msg.textContent='✗ request failed';}}
function addDom(){let d=dom.value.trim();if(d){domainRequest('/addblock?d=',d).then(()=>{if(allowmsg.textContent[0]=='✓')dom.value=''})}}
function addAllowDom(){let d=allowdom.value.trim();if(!d){allowmsg.textContent='✗ enter a domain';return;}domainRequest('/addallow?d=',d).then(()=>{if(allowmsg.textContent[0]=='✓')allowdom.value=''})}
async function saveUpstream(){let value=upstreamInput.value.trim();if(!value){upstreamMsg.textContent='✗ enter an IPv4 address';return;}upstreamMsg.textContent='saving...';try{let r=await fetch('/upstream',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ip='+encodeURIComponent(value)});let t=await r.text();upstreamMsg.textContent=r.ok?'✓ '+t:'✗ '+t;if(r.ok)await load();}catch(_){upstreamMsg.textContent='✗ request failed';}}
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24)).then(load)}
function fetchNow(){ustat.textContent='fetching...';fetch('/fetchnow').then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
upstreamForm.onsubmit=e=>{e.preventDefault();saveUpstream()};
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='flashing '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',body:fd});fwmsg.textContent=r.ok?'✓ rebooting, reconnect in ~15s':'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ rebooting, reconnect in ~15s';}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='uploading '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',body:fd});upmsg.textContent=r.ok?'✓ updated':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ upload failed';}
blf.value='';setTimeout(load,600);};
load();setInterval(load,3000);
)HTML"
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
R"HTML(
async function loadNetwork(){try{let r=await fetch('/network/status');if(!r.ok)throw Error(await r.text());let s=await r.json();let n=s.network;
if(!n){networkState.textContent='Network status is unavailable from this local address.';networkConfirm.style.display='none';return;}
networkState.textContent='Current IP: '+n.currentIP+' | New URL: '+n.newURL+' | '+n.status+(n.remainingMs!==undefined?' | '+Math.ceil(n.remainingMs/1000)+'s remaining':'');
let editingNetworkForm=networkForm.contains(document.activeElement);
if(!editingNetworkForm){networkMode.value=n.mode;if(n.local)networkIp.value=n.local;if(n.mask)networkMask.value=n.mask;if(n.gateway)networkGateway.value=n.gateway;if(n.dns)networkDns.value=n.dns;}
if(n.revision!==undefined){networkConfirm.style.display='inline-block';networkConfirm.textContent='Confirm '+n.newURL;networkConfirm.onclick=async()=>{let body='intent=confirm-network&revision='+encodeURIComponent(n.revision)+'&token='+encodeURIComponent(n.token);let c=await fetch('/network/confirm',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});networkMsg.textContent=c.ok?'✓ network confirmed':'✗ '+await c.text();if(c.ok)await loadNetwork();};}else networkConfirm.style.display='none';
}catch(e){networkState.textContent='Network status unavailable';}}
networkForm.onsubmit=async e=>{e.preventDefault();networkMsg.textContent='staging 180s trial...';let body='intent=network-change&mode='+encodeURIComponent(networkMode.value)+'&ip='+encodeURIComponent(networkIp.value.trim())+'&mask='+encodeURIComponent(networkMask.value.trim())+'&gateway='+encodeURIComponent(networkGateway.value.trim())+'&dns='+encodeURIComponent(networkDns.value.trim());let r=await fetch('/network/apply',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});networkMsg.textContent=r.ok?'✓ '+await r.text():'✗ '+await r.text();};
loadNetwork();setInterval(loadNetwork,3000);
async function doReset(path,intent,confirmText){if(!confirm(confirmText))return;resetMsg.textContent='resetting...';try{let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'intent='+intent});let t=await r.text();resetMsg.textContent=r.ok?'✓ '+t:'✗ '+t;}catch(_){resetMsg.textContent='✓ rebooting…'}}
resetConnectionBtn.onclick=()=>doReset('/network/reset-connection','connection-reset','Reset WiFi and network address settings? The device reboots into the setup portal.');
resetFactoryBtn.onclick=()=>doReset('/network/reset-factory','factory-reset','Factory reset? This clears WiFi, network address, upstream DNS, allowlist, bans, and update settings, then reboots with defaults. This cannot be undone.');
)HTML"
#endif
R"HTML(</script></body></html>)HTML";
