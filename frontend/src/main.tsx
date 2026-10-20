import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity, AlertTriangle, Bell, BookOpenCheck, ChevronRight, CircleDot, Cpu,
  Database, FileClock, Gauge, Globe2, HardDrive, Laptop, Menu, Network,
  Pause, Play, Radar, RefreshCw, Search, Settings, Shield, ShieldAlert,
  SlidersHorizontal, TestTube2, Users, Wifi, X
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis
} from 'recharts'
import './styles.css'

type Json = Record<string, unknown>
type Alert = {
  id: number; timestamp: string; severity: string; category: string; title: string;
  description: string; source: string; risk_score: number; confidence: number;
  status: string; evidence: Json; recommendation: string; mitre_technique?: string;
  simulated: boolean; incident_id?: number;
}
type Incident = {
  id: number; created_at: string; updated_at: string; title: string; severity: string;
  risk_score: number; status: string; summary: string; entities: Record<string, unknown[]>;
  alerts?: Alert[]; timeline?: {timestamp:string; title:string; severity:string; simulated:boolean}[];
  mitre_techniques?: string[]; investigation_steps?: string[];
}

const pages = [
  ['Dashboard', Gauge], ['Alerts', Bell], ['Incidents', ShieldAlert], ['Endpoint', Cpu],
  ['Network', Network], ['Security Audit', BookOpenCheck], ['Timeline', FileClock],
  ['Rules', SlidersHorizontal], ['Settings', Settings]
] as const
const colors: Record<string,string> = { INFO:'#3b82f6', LOW:'#22c55e', MEDIUM:'#f59e0b', HIGH:'#f97316', CRITICAL:'#ef4444' }

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {headers:{'Content-Type':'application/json'}, ...init})
  if (!response.ok) throw new Error((await response.text()) || `Request failed: ${response.status}`)
  return response.json()
}
const time = (value?: string) => value ? new Date(value).toLocaleString() : 'N/A'
const short = (value: unknown, length=70) => String(value ?? '').length > length ? `${String(value).slice(0,length)}...` : String(value ?? '')

function Severity({value}:{value:string}) {
  return <span className={`severity s-${value.toLowerCase()}`}><i />{value}</span>
}
function Status({value}:{value:string}) { return <span className={`status status-${value.toLowerCase()}`}>{value.replace('_',' ')}</span> }
function Empty({label='No data collected yet'}:{label?:string}) { return <div className="empty"><Radar size={30}/><span>{label}</span></div> }
function Modal({title, onClose, children}:{title:string;onClose:()=>void;children:React.ReactNode}) {
  return <div className="modal-backdrop" onMouseDown={onClose}><section className="modal" onMouseDown={e=>e.stopPropagation()}><header><h2>{title}</h2><button className="icon" onClick={onClose}><X/></button></header>{children}</section></div>
}

function DashboardPage({data, refresh}:{data:any;refresh:()=>void}) {
  if (!data) return <Empty label="Waiting for the first telemetry snapshot"/>
  const cards = [
    ['Active Alerts',data.counts.active_alerts,Bell],['Critical Alerts',data.counts.critical_alerts,ShieldAlert],
    ['Incidents',data.counts.incidents,AlertTriangle],['Processes',data.counts.processes,Cpu],
    ['Connections',data.counts.connections,Network],['Network Devices',data.counts.devices,Wifi],
    ['Security Findings',data.counts.findings,BookOpenCheck]
  ]
  return <>
    <div className="career-strip">
      <div><CircleDot/>SYSTEM <strong>ONLINE</strong></div><div><Activity/>MONITORING <strong>{data.monitoring?'ACTIVE':'PAUSED'}</strong></div>
      <div><Database/>DATABASE <strong>LOCAL</strong></div><div><Globe2/>CLOUD <strong>NOT REQUIRED</strong></div><div><Wifi/>INTERNET <strong>NOT REQUIRED</strong></div>
    </div>
    <div className="dashboard-head">
      <div className="risk-ring" style={{'--risk':`${data.risk_score*3.6}deg`} as React.CSSProperties}><div><strong>{data.risk_score}</strong><span>System Risk</span></div></div>
      <div><p className="eyebrow">LOCAL SECURITY OPERATIONS PLATFORM</p><h1>AegisSOC</h1><p>{data.disclaimer}</p><div className="privilege"><Shield size={16}/>Privileges: <b>{data.system.administrator?'Administrator':'Standard User'}</b>{!data.system.administrator&&<span>Some telemetry requires Administrator privileges.</span>}</div></div>
    </div>
    <div className="metric-grid">{cards.map(([label,value,Icon])=><article className="metric" key={label as string}><div className="metric-icon"><Icon/></div><div><span>{label}</span><strong>{value}</strong></div></article>)}</div>
    <div className="charts-grid">
      <article className="panel"><PanelTitle title="Alerts over time"/><div className="chart"><ResponsiveContainer><AreaChart data={data.alerts_over_time}><defs><linearGradient id="blue" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#22d3ee" stopOpacity={.5}/><stop offset="1" stopColor="#22d3ee" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#202a35" vertical={false}/><XAxis dataKey="time" stroke="#637184"/><YAxis allowDecimals={false} stroke="#637184"/><Tooltip contentStyle={{background:'#111820',border:'1px solid #2a3745'}}/><Area type="monotone" dataKey="alerts" stroke="#22d3ee" fill="url(#blue)"/></AreaChart></ResponsiveContainer></div></article>
      <article className="panel"><PanelTitle title="Alerts by severity"/><div className="chart"><ResponsiveContainer><PieChart><Pie data={data.alerts_by_severity} dataKey="value" nameKey="name" innerRadius={54} outerRadius={82} paddingAngle={3}>{data.alerts_by_severity.map((x:any)=><Cell key={x.name} fill={colors[x.name]}/>)}</Pie><Tooltip contentStyle={{background:'#111820',border:'1px solid #2a3745'}}/></PieChart></ResponsiveContainer></div><div className="legend">{data.alerts_by_severity.map((x:any)=><span key={x.name}><i style={{background:colors[x.name]}}/>{x.name} {x.value}</span>)}</div></article>
    </div>
    <div className="two-col"><article className="panel"><PanelTitle title="Recent alerts" action={refresh}/><AlertTable items={data.recent_alerts}/></article><article className="panel"><PanelTitle title="Recent incidents"/>{data.recent_incidents.length?<div className="incident-list">{data.recent_incidents.map((x:Incident)=><div key={x.id}><Severity value={x.severity}/><span><b>{x.title}</b><small>INC-{String(x.id).padStart(4,'0')} | {time(x.updated_at)}</small></span><strong>{x.risk_score}</strong></div>)}</div>:<Empty/>}</article></div>
  </>
}

function PanelTitle({title, action}:{title:string;action?:()=>void}) { return <div className="panel-title"><h3>{title}</h3>{action&&<button className="icon" onClick={action}><RefreshCw size={16}/></button>}</div> }
function AlertTable({items,onSelect}:{items:Alert[];onSelect?:(a:Alert)=>void}) {
  if (!items?.length) return <Empty label="No alerts"/>
  return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Detection</th><th>Source</th><th>Risk</th><th>Status</th></tr></thead><tbody>{items.map(a=><tr key={a.id} onClick={()=>onSelect?.(a)} className={onSelect?'clickable':''}><td>{time(a.timestamp)}</td><td><Severity value={a.severity}/></td><td><b>{a.title}</b>{a.simulated&&<span className="simulated">SIMULATED</span>}</td><td>{a.source}</td><td>{a.risk_score}</td><td><Status value={a.status}/></td></tr>)}</tbody></table></div>
}

function AlertsPage({version}:{version:number}) {
  const [items,setItems]=useState<Alert[]>([]), [selected,setSelected]=useState<Alert|null>(null)
  const [filters,setFilters]=useState({search:'',severity:'',status:'',category:''})
  const load=useCallback(()=>{const q=new URLSearchParams(Object.entries(filters).filter(([,v])=>v));api<Alert[]>(`/alerts?${q}`).then(setItems)},[filters,version])
  useEffect(load,[load])
  const patch=(status:string)=>selected&&api<Alert>(`/alerts/${selected.id}`,{method:'PATCH',body:JSON.stringify({status})}).then(x=>{setSelected({...selected,...x});load()})
  return <><Toolbar search={filters.search} setSearch={v=>setFilters({...filters,search:v})}>{['severity','status','category'].map(key=><select key={key} value={(filters as any)[key]} onChange={e=>setFilters({...filters,[key]:e.target.value})}><option value="">All {key}</option>{(key==='severity'?Object.keys(colors):key==='status'?['NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE']:['endpoint','network','file','windows','persistence','system']).map(v=><option key={v}>{v}</option>)}</select>)}</Toolbar><article className="panel"><AlertTable items={items} onSelect={setSelected}/></article>{selected&&<Modal title={`ALT-${String(selected.id).padStart(5,'0')} | ${selected.title}`} onClose={()=>setSelected(null)}><div className="detail-grid"><Field label="Severity"><Severity value={selected.severity}/></Field><Field label="Status"><Status value={selected.status}/></Field><Field label="Risk / confidence">{selected.risk_score} / {selected.confidence}%</Field><Field label="Timestamp">{time(selected.timestamp)}</Field><Field label="Source">{selected.source} / {selected.category}</Field><Field label="MITRE ATT&CK">{selected.mitre_technique||'Not mapped'}</Field></div><DetailBlock title="Description" value={selected.description}/><DetailBlock title="Evidence" value={JSON.stringify(selected.evidence,null,2)} mono/><DetailBlock title="Recommendation" value={selected.recommendation}/>{selected.incident_id&&<div className="notice">Linked to incident INC-{String(selected.incident_id).padStart(4,'0')}</div>}<div className="modal-actions"><button onClick={()=>patch('INVESTIGATING')}>Investigating</button><button onClick={()=>patch('RESOLVED')}>Resolve</button><button className="ghost" onClick={()=>patch('FALSE_POSITIVE')}>False Positive</button></div></Modal>}</>
}

function IncidentsPage({version}:{version:number}) {
  const [items,setItems]=useState<Incident[]>([]),[selected,setSelected]=useState<Incident|null>(null)
  const load=()=>api<Incident[]>('/incidents').then(setItems)
  useEffect(()=>{void load()},[version])
  const open=(id:number)=>api<Incident>(`/incidents/${id}`).then(setSelected)
  const patch=(status:string)=>selected&&api<Incident>(`/incidents/${selected.id}`,{method:'PATCH',body:JSON.stringify({status})}).then(()=>{open(selected.id);load()})
  return <><div className="incident-cards">{items.map(x=><article key={x.id} className="incident-card" onClick={()=>open(x.id)}><div><Severity value={x.severity}/><Status value={x.status}/></div><h3>{x.title}</h3><p>{x.summary}</p><footer><span>INC-{String(x.id).padStart(4,'0')}</span><strong>Risk {x.risk_score}</strong><ChevronRight/></footer></article>)}</div>{!items.length&&<Empty label="No incidents have been correlated"/>}{selected&&<Modal title={`INC-${String(selected.id).padStart(4,'0')} | ${selected.title}`} onClose={()=>setSelected(null)}><div className="detail-grid"><Field label="Severity"><Severity value={selected.severity}/></Field><Field label="Risk">{selected.risk_score}/100</Field><Field label="Status"><Status value={selected.status}/></Field><Field label="Created">{time(selected.created_at)}</Field></div><DetailBlock title="Summary" value={selected.summary}/><h3>Entities</h3><div className="entity-list">{Object.entries(selected.entities||{}).map(([k,v])=><span key={k}><b>{k}</b>{v.join(', ')}</span>)}</div><h3>Incident timeline</h3><div className="timeline">{selected.timeline?.map((x,i)=><div key={i}><i/><time>{time(x.timestamp)}</time><Severity value={x.severity}/><b>{x.title}</b>{x.simulated&&<span className="simulated">SIMULATED</span>}</div>)}</div><h3>MITRE techniques</h3><div className="tags">{selected.mitre_techniques?.map(x=><span key={x}>{x}</span>)}</div><h3>Recommended investigation steps</h3><ol>{selected.investigation_steps?.map(x=><li key={x}>{x}</li>)}</ol><div className="modal-actions"><button onClick={()=>patch('INVESTIGATING')}>Investigating</button><button onClick={()=>patch('RESOLVED')}>Resolve</button><button className="ghost" onClick={()=>patch('FALSE_POSITIVE')}>False Positive</button></div></Modal>}</>
}

function EndpointPage({version}:{version:number}) {
  const [data,setData]=useState<any>(),[search,setSearch]=useState(''),[selected,setSelected]=useState<any>()
  useEffect(()=>{api(`/processes?search=${encodeURIComponent(search)}`).then(setData)},[version,search])
  if(!data)return <Empty/>
  const metrics=[['CPU',`${data.system.cpu_percent}%`,Cpu],['RAM',`${data.system.ram_percent}%`,HardDrive],['Processes',data.count,Cpu],['Privilege',data.system.administrator?'Admin':'Standard',Shield]]
  return <><div className="mini-metrics">{metrics.map(([k,v,I])=><div key={k as string}><I/><span>{k}<b>{v}</b></span></div>)}</div><Toolbar search={search} setSearch={setSearch}/><article className="panel"><div className="table-wrap"><table><thead><tr><th>Name</th><th>PID</th><th>Parent</th><th>User</th><th>CPU</th><th>RAM</th><th>Path</th></tr></thead><tbody>{data.items.map((p:any)=><tr className="clickable" key={p.pid} onClick={()=>setSelected(p)}><td><b>{p.name}</b></td><td className="mono">{p.pid}</td><td>{p.parent||'N/A'}</td><td>{short(p.username,25)}</td><td>{p.cpu_percent}%</td><td>{p.ram_mb} MB</td><td className="mono">{short(p.path,45)}</td></tr>)}</tbody></table></div></article>{selected&&<ProcessModal value={selected} onClose={()=>setSelected(null)}/>}</>
}
function ProcessModal({value,onClose}:{value:any;onClose:()=>void}) {
  const [hash,setHash]=useState<string>('Not calculated')
  return <Modal title={`${value.name} | PID ${value.pid}`} onClose={onClose}><div className="detail-grid"><Field label="PID / PPID">{value.pid} / {value.ppid}</Field><Field label="Parent">{value.parent||'Unavailable'}</Field><Field label="User">{value.username||'Unavailable'}</Field><Field label="Started">{time(value.start_time)}</Field><Field label="CPU">{value.cpu_percent}%</Field><Field label="RAM">{value.ram_mb} MB</Field></div><DetailBlock title="Executable path" value={value.path||'Unavailable'} mono/><DetailBlock title="Command line" value={value.command_line||'Unavailable'} mono/><DetailBlock title="SHA-256" value={hash} mono/><button onClick={()=>api<any>(`/processes/${value.pid}/hash`).then(x=>setHash(x.sha256||'Skipped or unavailable'))}>Calculate executable hash</button></Modal>
}

function NetworkPage({version}:{version:number}) {
  const [data,setData]=useState<any>(); useEffect(()=>{api('/network').then(setData)},[version]); if(!data)return <Empty/>
  const info=data.information||{}; const active=(info.interfaces||[]).find((x:any)=>x.up&&x.ipv4?.length)||(info.interfaces||[])[0]
  return <><div className="network-summary"><article className="panel"><PanelTitle title="Network information"/><div className="kv"><span>Interface<b>{active?.name||'Unavailable'}</b></span><span>IPv4<b className="mono">{active?.ipv4?.join(', ')||'Unavailable'}</b></span><span>IPv6<b className="mono">{active?.ipv6?.join(', ')||'Unavailable'}</b></span><span>MAC<b className="mono">{active?.mac||'Unavailable'}</b></span><span>Gateway<b className="mono">{info.gateway||'Unavailable'}</b></span><span>DNS<b className="mono">{info.dns?.join(', ')||'Unavailable'}</b></span></div></article><article className="panel"><PanelTitle title="Wi-Fi"/><div className="kv"><span>SSID<b>{info.ssid||'Not connected or unavailable'}</b></span><span>BSSID<b className="mono">{info.bssid||'Unavailable'}</b></span><span>Signal<b>{info.signal||'Unavailable'}</b></span><span>Channel<b>{info.channel||'Unavailable'}</b></span><span>Radio type<b>{info.radio_type||'Unavailable'}</b></span><span>Security<b>{[info.authentication,info.cipher].filter(Boolean).join(' / ')||'Unavailable'}</b></span></div></article></div><article className="panel"><PanelTitle title={`Network devices (${data.devices.length})`}/><SimpleTable headers={['IP','MAC','State','Vendor']} rows={data.devices.map((x:any)=>[x.ip,x.mac,x.state,x.vendor])}/></article><article className="panel"><PanelTitle title={`Active connections (${data.connections.length})`}/><SimpleTable headers={['Process','PID','Local','Remote','Protocol','State']} rows={data.connections.map((x:any)=>[x.process,x.pid,`${x.local_ip||'*'}:${x.local_port||'*'}`,x.remote_ip?`${x.remote_ip}:${x.remote_port}`:'-',x.protocol,x.state])}/></article><article className="panel"><PanelTitle title={`Listening ports (${data.listening.length})`}/><SimpleTable headers={['Port','Protocol','Process','PID','Address']} rows={data.listening.map((x:any)=>[x.local_port,x.protocol,x.process,x.pid,x.local_ip])}/></article></>
}

function AuditPage() {
  const [items,setItems]=useState<any[]>([]),[running,setRunning]=useState(false),[summary,setSummary]=useState<any>({}),[risk,setRisk]=useState(0)
  useEffect(()=>{api<any[]>('/audit').then(setItems)},[])
  const run=()=>{setRunning(true);api<any>('/audit',{method:'POST'}).then(x=>{setItems(x.findings);setSummary(x.summary);setRisk(x.risk_score)}).finally(()=>setRunning(false))}
  return <><div className="audit-head"><div><p className="eyebrow">WINDOWS SECURITY POSTURE</p><h2>Quick security audit</h2><p>Checks common local configuration risks without changing the system.</p></div><button onClick={run} disabled={running}><RefreshCw className={running?'spin':''}/>{running?'Running audit':'Run Quick Audit'}</button></div><div className="mini-metrics"><div><Gauge/><span>System Risk<b>{risk}</b></span></div>{['CRITICAL','HIGH','MEDIUM','LOW'].map(x=><div key={x}><span>{x}<b>{summary[x]||items.filter(i=>i.severity===x).length}</b></span></div>)}</div><article className="panel"><div className="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Status</th><th>Details</th><th>Recommendation</th></tr></thead><tbody>{items.map((x:any,i)=><tr key={x.id||i}><td><Severity value={x.severity}/></td><td><b>{x.title}</b></td><td><Status value={x.status}/></td><td>{short(x.details,120)}</td><td>{short(x.recommendation,120)}</td></tr>)}</tbody></table></div>{!items.length&&<Empty label="Run the audit to create findings"/>}</article></>
}

function TimelinePage({version}:{version:number}) {
  const [items,setItems]=useState<any[]>([]),[category,setCategory]=useState(''),[severity,setSeverity]=useState('')
  useEffect(()=>{api<any[]>(`/timeline?category=${category}&severity=${severity}`).then(setItems)},[version,category,severity])
  return <><Toolbar search="" setSearch={()=>{}} hideSearch><select value={category} onChange={e=>setCategory(e.target.value)}><option value="">All categories</option>{['endpoint','network','file','windows','persistence','audit','system'].map(x=><option key={x}>{x}</option>)}</select><select value={severity} onChange={e=>setSeverity(e.target.value)}><option value="">All severities</option>{Object.keys(colors).map(x=><option key={x}>{x}</option>)}</select></Toolbar><article className="panel"><div className="global-timeline">{items.map(x=><div key={x.id}><span className="timeline-icon"><Activity/></span><time>{time(x.timestamp)}</time><Severity value={x.severity}/><span><b>{x.event_type.replaceAll('_',' ')}</b><small>{x.source} / {x.category} {x.simulated?' | SIMULATED':''}</small></span><code>{short(JSON.stringify(x.data),90)}</code></div>)}</div>{!items.length&&<Empty/>}</article></>
}

function RulesPage() {
  const [items,setItems]=useState<any[]>([]); const load=()=>api<any[]>('/rules').then(setItems); useEffect(()=>{void load()},[])
  const toggle=(x:any)=>api(`/rules/${x.id}`,{method:'PATCH',body:JSON.stringify({enabled:!x.enabled})}).then(load)
  return <article className="panel"><div className="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Enabled</th></tr></thead><tbody>{items.map(x=><tr key={x.id}><td className="mono">{x.id}</td><td><b>{x.name}</b><small className="block">{x.description}</small></td><td>{x.category}</td><td><Severity value={x.severity}/></td><td className="mono">{x.mitre?.technique||'-'}</td><td><button className={`toggle ${x.enabled?'on':''}`} onClick={()=>toggle(x)}><i/></button></td></tr>)}</tbody></table></div></article>
}

function SettingsPage() {
  const [value,setValue]=useState<any>(); const [saved,setSaved]=useState(false)
  useEffect(()=>{api('/settings').then(setValue)},[]); if(!value)return <Empty/>
  const save=()=>api<any>('/settings',{method:'PATCH',body:JSON.stringify(value)}).then(x=>{setValue(x);setSaved(true);setTimeout(()=>setSaved(false),1800)})
  return <div className="settings-page"><article className="panel"><PanelTitle title="Collectors"/>{[['process_monitor','Process monitor'],['network_monitor','Network monitor'],['file_monitor','File integrity monitoring'],['windows_events','Windows event monitoring']].map(([key,label])=><label className="setting-row" key={key}><span><b>{label}</b><small>Collector failures are isolated from the rest of the application.</small></span><input type="checkbox" checked={value[key]} onChange={e=>setValue({...value,[key]:e.target.checked})}/></label>)}</article><article className="panel"><PanelTitle title="Intervals and retention"/>{[['process_interval','Process interval, seconds'],['network_interval','Network interval, seconds'],['device_interval','Device interval, seconds'],['event_retention_days','Low-level event retention, days'],['max_hash_mb','Maximum hash size, MB']].map(([key,label])=><label className="input-row" key={key}><span>{label}</span><input type="number" value={value[key]} onChange={e=>setValue({...value,[key]:Number(e.target.value)})}/></label>)}</article><article className="panel full"><PanelTitle title="File integrity monitoring paths"/><textarea value={value.fim_paths.join('\n')} onChange={e=>setValue({...value,fim_paths:e.target.value.split('\n').filter(Boolean)})}/><small>One absolute folder path per line. Monitoring the whole system drive is intentionally discouraged.</small></article><button onClick={save}><Settings/>{saved?'Settings saved':'Save settings'}</button></div>
}

function Toolbar({search,setSearch,hideSearch=false,children}:{search:string;setSearch:(v:string)=>void;hideSearch?:boolean;children?:React.ReactNode}) { return <div className="toolbar">{!hideSearch&&<label className="search"><Search/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search..."/></label>}{children}</div> }
function SimpleTable({headers,rows}:{headers:string[];rows:unknown[][]}) { return rows.length?<div className="table-wrap"><table><thead><tr>{headers.map(x=><th key={x}>{x}</th>)}</tr></thead><tbody>{rows.map((row,i)=><tr key={i}>{row.map((x,j)=><td key={j} className={j===0||headers[j].includes('IP')||headers[j].includes('MAC')?'mono':''}>{String(x??'')}</td>)}</tr>)}</tbody></table></div>:<Empty/> }
function Field({label,children}:{label:string;children:React.ReactNode}) { return <div><small>{label}</small><b>{children}</b></div> }
function DetailBlock({title,value,mono=false}:{title:string;value:string;mono?:boolean}) { return <div className="detail-block"><h3>{title}</h3><pre className={mono?'mono':''}>{value}</pre></div> }

function App() {
  const [page,setPage]=useState('Dashboard'),[mobile,setMobile]=useState(false),[dashboard,setDashboard]=useState<any>(),[version,setVersion]=useState(0),[error,setError]=useState('')
  const refresh=useCallback(()=>{api('/dashboard').then(x=>{setDashboard(x);setError('')}).catch(e=>setError(e.message))},[])
  useEffect(()=>{refresh();const id=setInterval(()=>{refresh();setVersion(v=>v+1)},5000);let ws:WebSocket|undefined;let retry:number;const connect=()=>{ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws`);ws.onmessage=()=>{setVersion(v=>v+1);refresh()};ws.onclose=()=>{retry=window.setTimeout(connect,2000)}};connect();return()=>{clearInterval(id);clearTimeout(retry);ws?.close()}},[refresh])
  const monitor=()=>api('/monitoring',{method:'PATCH',body:JSON.stringify({active:!dashboard?.monitoring})}).then(refresh)
  const demo=()=>api('/demo/attack',{method:'POST'}).then(()=>setVersion(v=>v+1))
  const test=()=>api('/demo/alert',{method:'POST'}).then(()=>setVersion(v=>v+1))
  const content=useMemo(()=>{switch(page){case'Alerts':return <AlertsPage version={version}/>;case'Incidents':return <IncidentsPage version={version}/>;case'Endpoint':return <EndpointPage version={version}/>;case'Network':return <NetworkPage version={version}/>;case'Security Audit':return <AuditPage/>;case'Timeline':return <TimelinePage version={version}/>;case'Rules':return <RulesPage/>;case'Settings':return <SettingsPage/>;default:return <DashboardPage data={dashboard} refresh={refresh}/>}},[page,version,dashboard,refresh])
  return <div className="app"><aside className={mobile?'open':''}><div className="brand"><span><Shield/></span><div><b>AegisSOC</b><small>LOCAL SECURITY OPERATIONS</small></div><button className="icon close-nav" onClick={()=>setMobile(false)}><X/></button></div><nav>{pages.map(([label,Icon])=><button key={label} className={page===label?'active':''} onClick={()=>{setPage(label);setMobile(false)}}><Icon/>{label}</button>)}</nav><div className="side-foot"><div><span className={`pulse ${dashboard?.monitoring?'':'off'}`}/><p>MONITORING<b>{dashboard?.monitoring?'ACTIVE':'PAUSED'}</b></p></div><small>v1.0.0 | Local only</small></div></aside><main><header className="topbar"><button className="icon menu" onClick={()=>setMobile(true)}><Menu/></button><div><p className="eyebrow">AEGIS / {page.toUpperCase()}</p><h2>{page}</h2></div><div className="top-actions"><button className="ghost" onClick={test}><TestTube2/>Test Alert</button><button onClick={demo}><ShieldAlert/>Safe Attack Simulation</button><button className="ghost" onClick={monitor}>{dashboard?.monitoring?<Pause/>:<Play/>}{dashboard?.monitoring?'Pause':'Resume'}</button></div></header>{error&&<div className="error">API error: {error}</div>}<div className="content">{content}</div></main></div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
