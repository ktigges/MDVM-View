const state={catalog:null,dataset:"findings",offset:0,limit:50,query:"",selectedRecord:null};
const $=id=>document.getElementById(id);
const esc=value=>String(value??"").replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const fmt=value=>Number(value||0).toLocaleString();
let reauthenticationStarted=false;
let requestSequence=0,requestController;

async function apiFetch(path,options){
  const response=await fetch(path,options);
  if(response.status!==401)return response;
  if(!reauthenticationStarted){
    reauthenticationStarted=true;
    const returnPath=`${location.pathname}${location.search}${location.hash}`;
    location.assign(`/.auth/login/aad?post_login_redirect_uri=${encodeURIComponent(returnPath)}`);
  }
  throw new Error("Microsoft Entra sign-in expired; redirecting to sign in.");
}

function columns(rows){
  const preferred=["FindingKey","RecommendationName","CveId","Severity","DeviceName","FindingStatus","SlaStatus","DataOrigin","SnapshotTimeUtc","CollectionRunId"];
  const available=[...new Set(rows.flatMap(row=>Object.keys(row)))];
  return[...preferred.filter(field=>available.includes(field)),...available.filter(field=>!preferred.includes(field)).sort()].slice(0,12);
}

function selectRecord(row){
  state.selectedRecord=row;
  $("dataBrowserRecordTitle").textContent="Complete normalized record";
  $("dataBrowserJson").textContent=JSON.stringify(row,null,2);
  $("copyDataBrowserJson").disabled=false;
  $("copyDataBrowserJson").textContent="Copy JSON";
}

function renderRows(payload){
  state.selectedRecord=null;
  $("copyDataBrowserJson").disabled=true;
  $("copyDataBrowserJson").textContent="Copy JSON";
  $("dataBrowserJson").textContent="No record selected.";
  const fields=columns(payload.rows),start=payload.total?payload.offset+1:0,end=Math.min(payload.offset+payload.rows.length,payload.total);
  $("dataBrowserTitle").textContent=payload.label;
  $("dataBrowserPageStatus").textContent=`Showing ${fmt(start)}-${fmt(end)} of ${fmt(payload.total)}`;
  $("dataBrowserMetadata").innerHTML=`<strong>${esc(payload.label)}</strong><span>${esc(payload.description||"Exact normalized records used by the dashboard.")}</span><span>Source: ${esc(payload.source||"current dashboard bundle")} · ${fmt(payload.unfilteredTotal??payload.total)} total rows · ${fmt(fields.length)} displayed fields</span>`;
  $("dataBrowserTable").innerHTML=`<thead><tr>${fields.map(field=>`<th>${esc(field)}</th>`).join("")}</tr></thead><tbody>${payload.rows.map((row,index)=>`<tr data-index="${index}" tabindex="0">${fields.map(field=>`<td>${esc(typeof row[field]==="object"?JSON.stringify(row[field]):row[field])}</td>`).join("")}</tr>`).join("")}</tbody>`;
  $("dataBrowserTable").querySelectorAll("tbody tr").forEach((row,index)=>{
    row.addEventListener("click",()=>selectRecord(payload.rows[index]));
    row.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();selectRecord(payload.rows[index]);}});
  });
  $("dataBrowserPrevious").disabled=payload.offset===0;
  $("dataBrowserNext").disabled=payload.offset+payload.rows.length>=payload.total;
}

async function loadRows(){
  const sequence=++requestSequence;
  requestController?.abort();
  requestController=new AbortController();
  const parameters=new URLSearchParams({offset:String(state.offset),limit:String(state.limit),snapshotId:state.catalog.snapshot.snapshotId});
  if(state.query)parameters.set("query",state.query);
  $("dataBrowserMetadata").textContent="Loading curated records.";
  $("dataBrowserPrevious").disabled=true;
  $("dataBrowserNext").disabled=true;
  $("dataBrowserTable").innerHTML="";
  try{
    const response=await apiFetch(`/api/data-browser/${encodeURIComponent(state.dataset)}?${parameters}`,{cache:"no-store",signal:requestController.signal});
    const payload=await response.json();
    if(sequence!==requestSequence)return;
    if(!response.ok)throw new Error(payload.detail||`Dataset request failed: ${response.status}`);
    if(payload.snapshotId!==state.catalog.snapshot.snapshotId)throw new Error("The dataset snapshot changed. Reload this page.");
    renderRows(payload);
  }catch(error){
    if(sequence!==requestSequence||error.name==="AbortError")return;
    $("dataBrowserMetadata").textContent=`Data evidence unavailable: ${error.message}`;
    $("dataBrowserTable").innerHTML="";
    $("dataBrowserPageStatus").textContent="";
  }
}

async function loadCatalog(){
  try{
    const response=await apiFetch("/api/data-browser/catalog",{cache:"no-store"});
    if(!response.ok){const payload=await response.json().catch(()=>null);throw new Error(payload?.detail||`Catalog request failed: ${response.status}`);}
    state.catalog=await response.json();
    const dataset=$("dataBrowserDataset");
    dataset.innerHTML=state.catalog.datasets.map(item=>`<option value="${esc(item.id)}"${item.available===false?" disabled":""}>${esc(item.label)} · ${item.available===false?"unavailable":fmt(item.rowCount)}</option>`).join("");
    const available=state.catalog.datasets.filter(item=>item.available!==false);
    state.dataset=available.some(item=>item.id===state.dataset)?state.dataset:available[0]?.id||"";
    dataset.value=state.dataset;
    dataset.disabled=!state.dataset;
    $("dataBrowserSearch").disabled=!state.dataset;
    $("dataBrowserSearchButton").disabled=!state.dataset;
    if(state.dataset)await loadRows();
  }catch(error){
    $("dataBrowserDataset").innerHTML='<option value="">No datasets available</option>';
    $("dataBrowserMetadata").textContent=`Data evidence unavailable: ${error.message}`;
  }
}

$("dataBrowserDataset").addEventListener("change",event=>{state.dataset=event.target.value;state.offset=0;state.query="";$("dataBrowserSearch").value="";loadRows();});
$("dataBrowserSearchButton").addEventListener("click",()=>{state.query=$("dataBrowserSearch").value.trim();state.offset=0;loadRows();});
$("dataBrowserSearch").addEventListener("keydown",event=>{if(event.key==="Enter")$("dataBrowserSearchButton").click();});
$("dataBrowserPrevious").addEventListener("click",()=>{state.offset=Math.max(0,state.offset-state.limit);loadRows();});
$("dataBrowserNext").addEventListener("click",()=>{state.offset+=state.limit;loadRows();});
$("copyDataBrowserJson").addEventListener("click",()=>{if(!state.selectedRecord)return;navigator.clipboard?.writeText(JSON.stringify(state.selectedRecord,null,2)).then(()=>{$("copyDataBrowserJson").textContent="Copied";}).catch(()=>{$("copyDataBrowserJson").textContent="Copy unavailable";});});

loadCatalog();
