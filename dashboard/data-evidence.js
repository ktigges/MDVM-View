const state={catalog:null,dataset:"findings",offset:0,limit:50,query:"",selectedRecord:null};
const $=id=>document.getElementById(id);
const esc=value=>String(value??"").replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const fmt=value=>Number(value||0).toLocaleString();

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
  const parameters=new URLSearchParams({offset:String(state.offset),limit:String(state.limit)});
  if(state.query)parameters.set("query",state.query);
  $("dataBrowserMetadata").textContent="Loading curated records.";
  try{
    const response=await fetch(`/api/data-browser/${encodeURIComponent(state.dataset)}?${parameters}`,{cache:"no-store"});
    if(!response.ok)throw new Error(`Dataset request failed: ${response.status}`);
    renderRows(await response.json());
  }catch(error){
    $("dataBrowserMetadata").textContent=`Data evidence unavailable: ${error.message}`;
    $("dataBrowserTable").innerHTML="";
    $("dataBrowserPageStatus").textContent="";
  }
}

async function loadCatalog(){
  try{
    const response=await fetch("/api/data-browser/catalog",{cache:"no-store"});
    if(!response.ok){const payload=await response.json().catch(()=>null);throw new Error(payload?.detail||`Catalog request failed: ${response.status}`);}
    state.catalog=await response.json();
    const dataset=$("dataBrowserDataset");
    dataset.innerHTML=state.catalog.datasets.map(item=>`<option value="${esc(item.id)}">${esc(item.label)} · ${fmt(item.rowCount)}</option>`).join("");
    state.dataset=state.catalog.datasets.some(item=>item.id===state.dataset)?state.dataset:state.catalog.datasets[0]?.id||"";
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
