"use strict";
const $=(s)=>document.querySelector(s);
const RAW_SOURCES=[
{id:"osint-framework",label:"OSINT Framework",type:"tree",url:"https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json"},
{id:"awesome-osint",label:"Awesome OSINT",type:"markdown",url:"https://raw.githubusercontent.com/jivoi/awesome-osint/master/README.md"},
{id:"awesome-threat-intelligence",label:"Awesome Threat Intelligence",type:"markdown",url:"https://raw.githubusercontent.com/hslatman/awesome-threat-intelligence/main/README.md"}
];
const META_SOURCES=[
{name:"OSINT Framework",url:"https://osintframework.com/",kind:"TREE",desc:"Interaktywna mapa narzędzi i źródeł OSINT."},
{name:"Awesome OSINT",url:"https://github.com/jivoi/awesome-osint",kind:"CURATED",desc:"Duża, stale aktualizowana lista narzędzi i źródeł."},
{name:"Bellingcat Toolkit",url:"https://bellingcat.gitbook.io/toolkit",kind:"INVESTIGATION",desc:"Praktyczne narzędzia dla śledztw online i geolokalizacji."},
{name:"OSINT.dev",url:"https://osint.dev/",kind:"DIRECTORY",desc:"Indeks źródeł OSINT z metadanymi i oceną dostępu."},
{name:"OpenOSINT",url:"https://openosint.tech/",kind:"AGENT",desc:"Open-source OSINT tooling przygotowany pod workflow agentowe."},
{name:"IntelTechniques",url:"https://inteltechniques.com/tools/",kind:"SEARCH",desc:"Zestawy wyszukiwarek i formularzy do ręcznego OSINT."},
{name:"OSINT Combine",url:"https://www.osintcombine.com/tools",kind:"TRAINING",desc:"Narzędzia, materiały i workflow dla analityków."},
{name:"Awesome Threat Intelligence",url:"https://github.com/hslatman/awesome-threat-intelligence",kind:"CTI",desc:"Źródła i platformy cyber threat intelligence."}
];
const state={tools:[],filtered:[],limit:120,sourceStatus:{},activeCategory:""};

function normUrl(raw){
 try{
  const u=new URL(raw);
  if(!/^https?:$/.test(u.protocol))return "";
  u.hash="";u.hostname=u.hostname.toLowerCase();
  if(u.pathname!=="/")u.pathname=u.pathname.replace(/\/+$/,"");
  return u.toString();
 }catch{return ""}
}
function clean(x){return String(x||"").replace(/\s+/g," ").trim()}
function catalogOnly(t){
 const text=(t.category+" "+t.name+" "+t.description).toLowerCase();
 return /password crack|credential attack|exploit|masscan|social engineering|phishing|bruteforce|brute force|ddos|payload|malware/.test(text);
}
function makeTool(t){
 const url=normUrl(t.url);if(!url)return null;
 const out={name:clean(t.name)||new URL(url).hostname,url:url,description:clean(t.description),category:clean(t.category)||"Uncategorized",source:t.source,api:!!t.api,local:!!t.local,registration:!!t.registration,opsec:clean(t.opsec).toLowerCase(),pricing:clean(t.pricing),runtime:!!t.runtime,catalogOnly:!!t.catalogOnly};
 out.catalogOnly=out.catalogOnly||catalogOnly(out);
 return out;
}
function parseTree(data,source){
 const out=[];
 function walk(node,path){
  path=path||[];
  const name=clean(node.name);
  if(node.type==="url"&&node.url){
   const t=makeTool({name:name,url:node.url,description:node.description,category:path.join(" / ")||"Uncategorized",source:source,api:node.api,local:node.localInstall,registration:node.registration,opsec:node.opsec,pricing:node.pricing});
   if(t)out.push(t);
  }
  const next=node.type==="folder"&&name&&name!=="OSINT Framework"?path.concat([name]):path;
  (node.children||[]).forEach((c)=>walk(c,next));
 }
 walk(data,[]);return out;
}
function parseMarkdown(md,source){
 const out=[];let heading="Uncategorized";
 md.split(/\r?\n/).forEach((line)=>{
  const hm=line.match(/^#{2,4}\s+(.+)/);
  if(hm){heading=clean(hm[1].replace(/[↑#*_\x60]/g,""));return}
  const re=/\[([^\]]{2,160})\]\((https?:\/\/[^\s)]+)(?:\s+["'][^"']*["'])?\)/g;
  let m;
  while((m=re.exec(line))){
   const name=clean(m[1].replace(/[*_\x60]/g,""));
   if(/badge|table of contents|license|contributing/i.test(name))continue;
   const desc=clean(line.replace(m[0],"").replace(/^\s*[-*+]\s*/,"").replace(/^\s*[-–—:]\s*/,""));
   const t=makeTool({name:name,url:m[2],description:desc,category:heading,source:source});
   if(t)out.push(t);
  }
 });
 return out;
}
function mergeTools(items){
 const map=new Map();
 items.forEach((item)=>{
  const key=normUrl(item.url).toLowerCase();if(!key)return;
  const old=map.get(key);
  if(!old){item.sources=[item.source];item.categories=[item.category];map.set(key,item);return}
  old.sources=[...new Set(old.sources.concat([item.source]))];
  old.categories=[...new Set(old.categories.concat([item.category]))];
  old.source=old.sources.join(" + ");old.category=old.categories.join(" / ");
  if(item.description.length>old.description.length)old.description=item.description;
  old.api=old.api||item.api;old.local=old.local||item.local;old.registration=old.registration||item.registration;old.runtime=old.runtime||item.runtime;old.catalogOnly=old.catalogOnly||item.catalogOnly;
  if(!old.opsec)old.opsec=item.opsec;
 });
 return [...map.values()].sort((a,b)=>a.name.localeCompare(b.name));
}
async function loadRuntime(){
 const out=[];
 try{
  const r=await fetch("/api/v1/health",{cache:"no-store"});if(!r.ok)return out;
  const h=await r.json();
  const src=((h.research||{}).sources||[]);
  src.forEach((s)=>{
   const t=makeTool({name:s.name,url:"/",description:(s.family||"Sherlock native source")+" · "+(s.ready?"READY":"GATED"),category:"Sherlock Runtime / "+(s.family||"SOURCE"),source:"Sherlock Runtime",api:true,local:!s.network_effect,runtime:true,opsec:"controlled"});
   if(t)out.push(t);
  });
 }catch{}
 return out;
}
async function sync(){
 $("#sync-state").textContent="SYNCING";$("#refresh").disabled=true;
 const all=[];state.sourceStatus={};
 for(const src of RAW_SOURCES){
  try{
   const r=await fetch(src.url,{cache:"no-store"});if(!r.ok)throw new Error("HTTP "+r.status);
   const text=await r.text();
   all.push(...(src.type==="tree"?parseTree(JSON.parse(text),src.label):parseMarkdown(text,src.label)));
   state.sourceStatus[src.id]={ok:true,label:src.label};
  }catch(err){state.sourceStatus[src.id]={ok:false,label:src.label,error:String(err)}}
 }
 const runtime=await loadRuntime();all.push(...runtime);state.sourceStatus.runtime={ok:true,label:"Sherlock Runtime"};
 state.tools=mergeTools(all);state.limit=120;
 buildFilters();renderSources();applyFilters();
 $("#stat-total").textContent=state.tools.length.toLocaleString("pl-PL");
 $("#stat-categories").textContent=new Set(state.tools.map((x)=>x.category.split(" / ")[0])).size;
 $("#stat-sources").textContent=Object.values(state.sourceStatus).filter((x)=>x.ok).length;
 $("#stat-runtime").textContent=state.tools.filter((x)=>x.runtime).length;
 $("#sync-state").textContent="LIVE";$("#sync-state").style.color="var(--green)";$("#refresh").disabled=false;
}
function renderSources(){
 const el=$("#source-strip");el.replaceChildren();
 Object.values(state.sourceStatus).forEach((v)=>{
  const d=document.createElement("div");d.className="source-pill "+(v.ok?"ok":"error");
  const dot=document.createElement("i"),b=document.createElement("strong"),s=document.createElement("span");
  b.textContent=v.label;s.textContent=v.ok?"SYNCED":"FAILED";d.append(dot,b,s);el.append(d);
 });
}
function buildFilters(){
 const source=$("#source-filter"),cat=$("#category-filter"),sv=source.value,cv=cat.value;
 source.innerHTML='<option value="">ALL SOURCES</option>';cat.innerHTML='<option value="">ALL CATEGORIES</option>';
 const sources=[...new Set(state.tools.flatMap((t)=>t.sources||[t.source]))].sort();
 const cats=[...new Set(state.tools.map((t)=>t.category.split(" / ")[0]))].sort();
 sources.forEach((x)=>{const o=document.createElement("option");o.value=x;o.textContent=x;source.append(o)});
 cats.forEach((x)=>{const o=document.createElement("option");o.value=x;o.textContent=x;cat.append(o)});
 source.value=sv;cat.value=cv;
 const chips=$("#category-chips");chips.replaceChildren();
 cats.slice(0,48).forEach((x)=>{
  const b=document.createElement("button");b.className="chip"+(state.activeCategory===x?" active":"");b.textContent=x;
  b.onclick=()=>{state.activeCategory=state.activeCategory===x?"":x;cat.value=state.activeCategory;buildFilters();applyFilters()};chips.append(b);
 });
}
function modeMatch(t,m){
 if(!m)return true;
 if(m==="runtime")return t.runtime;if(m==="api")return t.api;if(m==="local")return t.local;if(m==="passive")return t.opsec==="passive";if(m==="active")return t.opsec==="active";if(m==="catalog")return t.catalogOnly;return true;
}
function applyFilters(){
 const q=$("#q").value.trim().toLowerCase(),source=$("#source-filter").value,cat=$("#category-filter").value,mode=$("#mode-filter").value;
 state.filtered=state.tools.filter((t)=>{
  const blob=[t.name,t.description,t.category,t.source,t.url,t.pricing,t.opsec].join(" ").toLowerCase();
  return (!q||blob.includes(q))&&(!source||(t.sources||[t.source]).includes(source))&&(!cat||t.category.startsWith(cat))&&modeMatch(t,mode);
 });
 $("#visible-count").textContent=state.filtered.length.toLocaleString("pl-PL")+" MATCHES";
 $("#result-title").textContent=q?'Wyniki dla "'+$("#q").value.trim()+'"':"Wszystkie zasoby";
 renderTools();
}
function mkTag(text,cls){
 const s=document.createElement("span");s.className="tag "+(cls||"");s.textContent=text;return s;
}
function renderTools(){
 const grid=$("#tool-grid");grid.replaceChildren();
 const visible=state.filtered.slice(0,state.limit);
 if(!visible.length){const e=document.createElement("div");e.className="empty";e.textContent="Brak zasobów dla tych filtrów.";grid.append(e)}
 visible.forEach((t)=>{
  const a=document.createElement("article");a.className="tool";
  const head=document.createElement("div");head.className="tool-head";
  const lhs=document.createElement("div"),src=document.createElement("span"),h=document.createElement("h3");
  src.className="source";src.textContent=t.source;h.textContent=t.name;lhs.append(src,h);head.append(lhs);
  const p=document.createElement("p");p.textContent=t.description||new URL(t.url).hostname;
  const tags=document.createElement("div");tags.className="tags";
  if(t.runtime)tags.append(mkTag("SHERLOCK LIVE","runtime"));if(t.api)tags.append(mkTag("API"));if(t.local)tags.append(mkTag("LOCAL"));if(t.registration)tags.append(mkTag("REGISTRATION"));if(t.opsec)tags.append(mkTag(t.opsec.toUpperCase(),t.opsec==="active"?"active":""));if(t.pricing)tags.append(mkTag(t.pricing.toUpperCase()));if(t.catalogOnly)tags.append(mkTag("CATALOG ONLY","restricted"));
  const foot=document.createElement("div");foot.className="tool-foot";
  const c=document.createElement("span");c.className="category";c.textContent=t.category;
  const open=document.createElement("a");open.className="open";open.href=t.url;open.target="_blank";open.rel="noopener noreferrer";open.textContent="OPEN ↗";
  foot.append(c,open);a.append(head,p,tags,foot);grid.append(a);
 });
 $("#load-more").hidden=state.filtered.length<=state.limit;
}
function renderMeta(){
 const g=$("#meta-grid");g.replaceChildren();
 META_SOURCES.forEach((m)=>{
  const a=document.createElement("a");a.className="meta-card";a.href=m.url;a.target="_blank";a.rel="noopener noreferrer";
  const k=document.createElement("small"),n=document.createElement("strong"),p=document.createElement("p");
  k.textContent=m.kind;n.textContent=m.name;p.textContent=m.desc;a.append(k,n,p);g.append(a);
 });
}
$("#q").addEventListener("input",()=>{state.limit=120;applyFilters()});
["source-filter","category-filter","mode-filter"].forEach((id)=>$("#"+id).addEventListener("change",()=>{state.limit=120;applyFilters()}));
$("#refresh").onclick=sync;$("#load-more").onclick=()=>{state.limit+=120;renderTools()};
renderMeta();sync();