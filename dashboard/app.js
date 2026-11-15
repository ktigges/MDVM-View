/**
 * Author: Kevin Tigges
 * Last modified: 2026-11-10
 * Purpose: Request snapshot-pinned reports and render the interactive dashboard.
 */

const presentation=window.VULNERABILITY_VIEW_CONFIG||{};
const filterConfig=presentation.filters||{};
const workloadGroupingConfig=presentation.workloadGrouping||{};
const DEFAULT_RECOMMENDATION_TYPES=filterConfig.defaultRecommendationTypes||["Vulnerability"];
const DEFAULT_DOMAINS=filterConfig.defaultDomains||["Devices","Cloud"];
const DEFAULT_REPORTING_DAYS=[7,14,30,60,90].includes(Number(filterConfig.defaultReportingDays))?Number(filterConfig.defaultReportingDays):30;
if("scrollRestoration" in history)history.scrollRestoration="manual";
window.addEventListener("pageshow",()=>requestAnimationFrame(()=>window.scrollTo(0,0)));
const state={runHistory:[],runs:[],secureScores:[],slaPolicy:null,recommendationTracking:new Map(),recommendationsById:new Map(),subscriptionInventoryById:new Map(),vulnerabilityDetailsById:new Map(),watchlistCves:new Map(),origin:"Both",osType:"All",reportingBreakdown:"All",severity:filterConfig.defaultSeverity||"All",exposureStatus:"DetectedAndPending",assetClass:"All",subscription:"All",hideNonReporting:Boolean(filterConfig.defaultHideNonReporting),includeInactive:false,reportingDays:DEFAULT_REPORTING_DAYS,includeDiscoveredOnly:Boolean(filterConfig.defaultIncludeDiscoveredOnly),recommendationTypes:new Set(DEFAULT_RECOMMENDATION_TYPES),recommendationTrackingFilter:"All",recommendationCatalogStatus:"Unresolved exposure",recommendationCatalogSort:"priority",recommendationTrackingEnabled:false,recommendationTrackingLocalPreview:false,team:"All",search:"",domains:new Set(DEFAULT_DOMAINS),newPeriod:"day",newPeriodFilter:false,remediationPeriodFilter:false,latestRunChangesOnly:false,newPeriodStart:"",newPeriodEnd:"",statisticsPeriod:"week",reportingEntity:"machines",reportingChange:"Fixed",executiveSnapshotPeriod:"30days",executiveSnapshotStart:"",executiveSnapshotEnd:"",executiveSnapshotSubscription:"All",executiveSnapshotOwner:"All",executiveSnapshotUnit:"machines",selectedRecommendationId:"",detailRecommendationIds:[],selectedEntity:null,selectedCveDialogId:"",pivotSourceLabel:"",snapshotTimeMs:NaN,activeView:"executive"};
const PRIMARY_VIEWS={executive:"Summary",overview:"Vulnerabilities",recommendations:"Recommendations",workstations:"Machines",slaDashboard:"SLA",trend:"Reporting",executiveSnapshot:"Executive View",jobHistory:"Job history"};
let primaryView="executive";
state.slaEntity="cves";
const DEFENDER_RECOMMENDATIONS_URL="https://security.microsoft.com/exposure-recommendations?tabId=Devices";
const DEFENDER_VULNERABILITIES_URL="https://security.microsoft.com/vulnerabilities/devices";
const MAX_CUSTOMER_LOGO_BYTES=2*1024*1024;
const FINDINGS_PAGE_SIZE=100;
const findingsList={mode:"cves",page:0,scopeKey:""};
let pivotFilterRestore=null;
state.machineHistory={enabled:false,period:"30days",start:"",end:""};
state.machineCveStatus="All";
state.slaCompliance={start:"",end:""};
state.slaSummary={severity:"All",status:""};
state.managementMetric=null;
/** Find a dashboard element by ID. */
const $=id=>document.getElementById(id);
/** Interpret supported boolean representations. */
const truthy=value=>value===true||value==="True"||value==="true";
function findingLifecycleLabel(status){return{Open:"Open",Inactive:"Open – inactive device",Reopened:"Open",DetectionReturned:"Open",PendingConfirmation:"Open – inactive device",PendingVerification:"Open – inactive device",Fixed:"Fixed",StaleDevice:"Open – inactive device",OutOfScope:"Open – inactive device",Unknown:"Open – inactive device"}[status]||status||"Unknown";}
function findingLifecycleDescription(status){const inactive="Still open. The device has not been seen for 7 days, or this software item was not detected in the latest collection. It never counts as fixed and is shown only when Include inactive devices is on.";return{Open:"Defender currently reports this vulnerability on the device. It stays open until Defender no longer detects it.",Reopened:"Defender reports this vulnerability again after it was fixed. It is a new episode with a new SLA clock.",DetectionReturned:"Defender reports this vulnerability again. It is open.",Fixed:"Defender no longer detects this software item on an active device. A machine/CVE pair is fixed only when none of its software is still detected.",Inactive:inactive,PendingConfirmation:inactive,PendingVerification:inactive,StaleDevice:inactive,OutOfScope:inactive,Unknown:inactive}[status]||"Lifecycle state reported by Vulnerability View.";}
function fixRecognitionDescription(){
  const runs=state.slaPolicy?.lifecycle?.fixedConfirmationRuns;
  return Number.isInteger(runs)&&runs>1
    ?`This snapshot uses ${runs} consecutive qualified absent collections before counting a fix.`
    :"A fix counts at the first complete collection showing it absent on an active, recently reporting machine; no extra collection is required.";
}
/** Format a numeric value for display. */
const fmt=value=>Number(value||0).toLocaleString();
/** Escape a value for safe HTML rendering. */
const esc=value=>String(value??"").replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
/** Format a timestamp in UTC for display. */
const formatUtc=value=>{const date=new Date(value);return Number.isFinite(date.getTime())?`${date.toISOString().slice(0,19).replace("T"," ")} UTC`:"Unknown UTC time";};
/** Format a timestamp in the browser's local time zone. */
const formatLocal=value=>{const date=new Date(value);if(!Number.isFinite(date.getTime()))return"Unknown local time";const pad=value=>String(value).padStart(2,"0"),zone=new Intl.DateTimeFormat(undefined,{timeZoneName:"short"}).formatToParts(date).find(part=>part.type==="timeZoneName").value;return`${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())} ${zone}`;};
const displayDateTime=(column,value)=>/(?:Utc|DateTime)$/.test(column)&&value?formatUtc(value):value;
let reauthenticationStarted=false;
/** Fetch a dashboard API and restart Easy Auth when the browser session expires. */
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

let brandingStatusTimer;
/** Display branding upload status without disrupting the dashboard. */
function showBrandingStatus(message,error=false){clearTimeout(brandingStatusTimer);const status=$("brandingStatus");status.textContent=message;status.classList.toggle("error",error);status.hidden=false;brandingStatusTimer=setTimeout(()=>{status.hidden=true;},error?10000:5000);}
/** Display the newest server-managed customer logo when one exists. */
async function loadCustomerLogo(showReadError=false){
  const response=await apiFetch(`/api/branding/logo?version=${Date.now()}`,{cache:"no-store"});
  if(response.status===404)return false;
  if(!response.ok){if(showReadError)showBrandingStatus("Customer logo could not be loaded.",true);return false;}
  const customerLogo=$("customerLogo"),previous=customerLogo.dataset.objectUrl||"",objectUrl=URL.createObjectURL(await response.blob());
  customerLogo.src=objectUrl;customerLogo.dataset.objectUrl=objectUrl;customerLogo.hidden=false;$("defaultLogo").hidden=true;
  if(previous)URL.revokeObjectURL(previous);
  return true;
}
/** Configure administrator-only customer-logo controls. */
function configureBranding(auth){const canManage=Boolean(auth.authorization?.brandingAdministrator),button=$("brandLogoButton");button.disabled=!canManage;button.classList.toggle("can-manage",canManage);button.title=canManage?"Change customer logo":"";button.setAttribute("aria-label",canManage?"Change customer logo":"Customer logo");loadCustomerLogo(canManage);}
/** Show the identity and relevant application access of the current hosted user. */
function configureSignedInUser(auth){
  const container=$("signedInUser"),name=String(auth.user?.displayName||"").trim();
  if(!auth.authenticated||!name){container.hidden=true;return;}
  const initials=name.split(/\s+/).filter(Boolean).slice(0,2).map(part=>part[0]).join("").toUpperCase();
  $("signedInUserInitials").textContent=initials||"U";
  $("signedInUserName").textContent=name;
  $("signedInUserAccess").textContent=auth.authorization?.brandingAdministrator?"Dashboard Administrator":"Dashboard Viewer";
  container.title=`Signed in as ${name}`;
  container.hidden=false;
}
/** Return recent overall collection runs, with a grouped fallback for older exports. */
function recentCollectionRuns(){
  const preferredOrigin=state.origin==="Both"?"Live":state.origin,history=state.runHistory.filter(row=>!preferredOrigin||row.DataOrigin===preferredOrigin);
  if(history.length)return history.slice().sort((a,b)=>String(b.SnapshotTimeUtc).localeCompare(String(a.SnapshotTimeUtc))).slice(0,10);
  const grouped=new Map(),rank={Failed:3,PartialSuccess:2,Warning:2,Success:1};
  state.runs.filter(row=>!preferredOrigin||row.DataOrigin===preferredOrigin).forEach(row=>{
    const id=String(row.CollectionRunId||row.SnapshotTimeUtc||row.RunTimeUtc||"");if(!id)return;
    const item=grouped.get(id)||{CollectionRunId:id,SnapshotTimeUtc:row.SnapshotTimeUtc||row.RunTimeUtc,DataOrigin:row.DataOrigin,RunStatus:"Success"};
    if((rank[row.RunStatus]||2)>(rank[item.RunStatus]||1))item.RunStatus=row.RunStatus||"PartialSuccess";
    grouped.set(id,item);
  });
  return[...grouped.values()].sort((a,b)=>String(b.SnapshotTimeUtc).localeCompare(String(a.SnapshotTimeUtc))).slice(0,10);
}
/** Render recent collector execution evidence in the freshness tooltip. */
function renderRecentRuns(){
  const rows=recentCollectionRuns(),list=$("recentRunsList");
  if(!rows.length){list.innerHTML='<li class="empty">No collection history is available.</li>';return;}
  const statusLabel=status=>status==="PartialSuccess"?"Partial success":status||"Unknown";
  list.innerHTML=rows.map(row=>{
    const status=statusLabel(row.RunStatus),metrics=Number.isInteger(row.ActiveCves)&&Number.isInteger(row.AffectedMachines)?`${fmt(row.ActiveCves)} published unresolved CVEs · ${fmt(row.AffectedMachines)} affected machines`:row.RunStatus==="Failed"?"Collection failed":"Published CVE/machine counts unavailable";
    let explanation="";
    if(["PartialSuccess","Warning"].includes(row.RunStatus)){
      const issues=state.runs.filter(source=>source.DataOrigin===row.DataOrigin&&(row.CollectionRunId?source.CollectionRunId===row.CollectionRunId:(source.SnapshotTimeUtc||source.RunTimeUtc)===row.SnapshotTimeUtc)&&source.RunStatus!=="Success");
      explanation='<small class="recent-run-explanation">Completed with collection warnings, not still running. One or more sources reported a warning or did not complete successfully; some data may be missing or stale.</small>';
      explanation+=issues.length?issues.map(source=>`<small class="recent-run-explanation">${esc(source.Endpoint||"Unknown source")}: ${esc(statusLabel(source.RunStatus))}${source.Error?` - ${esc(source.Error)}`:""}</small>`).join(""):'<small class="recent-run-explanation">Per-source details are unavailable for this historical run.</small>';
    }
    return`<li><span><strong>${esc(formatLocal(row.SnapshotTimeUtc))}</strong><small>UTC: ${esc(formatUtc(row.SnapshotTimeUtc))}</small><small>${esc(metrics)}</small>${explanation}</span><b>${esc(status)}</b></li>`;
  }).join("");
}
/** Validate and upload a selected customer-logo PNG. */
async function uploadCustomerLogo(file){
  if(!file)return;
  if(file.type!=="image/png"&&!file.name.toLowerCase().endsWith(".png")){showBrandingStatus("Choose a PNG image.",true);return;}
  if(file.size>MAX_CUSTOMER_LOGO_BYTES){showBrandingStatus("The customer logo must be 2 MB or smaller.",true);return;}
  showBrandingStatus("Uploading customer logo...");
  try{
    const response=await apiFetch("/api/branding/logo",{method:"PUT",headers:{"Content-Type":"image/png"},body:file});
    if(!response.ok){const payload=await response.json().catch(()=>({}));throw new Error(payload.detail||`Upload failed with status ${response.status}`);}
    await loadCustomerLogo(true);showBrandingStatus("Customer logo updated.");
  }catch(error){showBrandingStatus(error.message||"Customer logo could not be updated.",true);}
}
/** Expand or collapse the desktop workspace navigation. */
function setNavigationCollapsed(collapsed,persist=false){document.body.classList.toggle("nav-collapsed",collapsed);const toggle=$("navToggle");toggle.setAttribute("aria-expanded",String(!collapsed));toggle.setAttribute("aria-label",collapsed?"Expand navigation":"Collapse navigation");toggle.title=collapsed?"Expand navigation":"Collapse navigation";if(persist)localStorage.setItem("vulnerability-view.navigation-collapsed.v1",String(collapsed));}
/** Keep the expanded desktop filter panel inside the visible viewport. */
function sizeFilterPanel(){const panel=$("filterBar");if(panel.hidden||matchMedia("(max-width: 650px)").matches){panel.style.removeProperty("max-height");return;}const available=Math.max(240,window.innerHeight-panel.getBoundingClientRect().top-12);panel.style.setProperty("max-height",`${available}px`,"important");}
/** Expand or collapse dashboard filters. */
function setFilterExpanded(expanded,persist=false){$("filterBar").hidden=!expanded;const controls=document.querySelector(".workspace-controls");controls?.classList.toggle("filters-open",expanded);const label=expanded?"Hide filters":"Show filters";$("filterToggle").setAttribute("aria-expanded",String(expanded));$("filterToggle").setAttribute("aria-label",label);$("filterToggle").title=label;$("filterToggle").textContent=expanded?"Filters open":"Filters";if(expanded){if(persist)controls?.scrollIntoView({block:"nearest"});requestAnimationFrame(sizeFilterPanel);}else $("filterBar").style.removeProperty("max-height");if(persist)localStorage.setItem("vulnerability-view.filters-expanded.v2",String(expanded));}
window.addEventListener("resize",sizeFilterPanel);
/** Apply presentation settings to dashboard content. */
function applyPresentationConfig(){
  const branding=presentation.branding||{},theme=presentation.theme||{},navigation=presentation.navigation||{},validColor=value=>/^#[0-9a-f]{6}$/i.test(value||"");
  if(branding.eyebrow)document.querySelector(".topbar .eyebrow").textContent=branding.eyebrow;
  if(branding.title){document.querySelector(".topbar h1").textContent=branding.title;document.title=branding.title;}
  const logo=branding.customerLogo||{},customerLogo=$("customerLogo"),customLogoEnabled=logo.enabled===true;
  if(logo.src)customerLogo.src=logo.src;
  if(logo.alt)customerLogo.alt=logo.alt;
  customerLogo.hidden=!customLogoEnabled;
  $("defaultLogo").hidden=customLogoEnabled;
  if(validColor(theme.primary))document.documentElement.style.setProperty("--navy",theme.primary);
  if(validColor(theme.accent))document.documentElement.style.setProperty("--cyan",theme.accent);
  $("revisionText").textContent=`Web version ${presentation.version||"unversioned"}`;
  $("revisionText").title=`UI revision ${presentation.revision?formatUtc(presentation.revision):"not specified"}`;
  document.documentElement.dataset.density=["compact","comfortable"].includes(theme.density)?theme.density:"comfortable";
  const nav=$("primaryNavigation"),buttons=[...document.querySelectorAll(".story-nav button[data-view]")],hidden=new Set(navigation.hidden||[]);
  (navigation.order||[]).forEach(view=>{const button=buttons.find(item=>item.dataset.view===view);if(button)nav.appendChild(button);});
  buttons.forEach(button=>{button.hidden=hidden.has(button.dataset.view);button.setAttribute("aria-label",PRIMARY_VIEWS[button.dataset.view]);});
  const firstVisible=buttons.find(button=>!button.hidden),active=buttons.find(button=>button.classList.contains("active")&&!button.hidden);
  if(!active&&firstVisible){buttons.forEach(button=>button.classList.remove("active"));firstVisible.classList.add("active");state.activeView=firstVisible.dataset.view;document.querySelectorAll(".story").forEach(section=>section.classList.toggle("active",section.id===state.activeView));}
  $("severityFilter").value=state.severity;
  $("hideNonReporting").checked=state.hideNonReporting;
  $("includeInactive").checked=state.includeInactive;
  $("reportingDays").value=String(state.reportingDays);
  $("reportingDays").disabled=!state.hideNonReporting;
  $("includeDiscoveredAssets").checked=state.includeDiscoveredOnly;
  document.querySelectorAll('input[name="recommendationType"]').forEach(input=>input.checked=state.recommendationTypes.has(input.value));
  document.querySelectorAll('input[name="assetDomain"]').forEach(input=>input.checked=state.domains.has(input.value));
  const saved=localStorage.getItem("vulnerability-view.filters-expanded.v2"),expanded=saved===null?filterConfig.expandedByDefault!==false:saved==="true";
  setFilterExpanded(expanded);
  setNavigationCollapsed(localStorage.getItem("vulnerability-view.navigation-collapsed.v1")==="true");
}
applyPresentationConfig();

apiFetch("/api/health").then(response=>response.ok?response.json():null).then(runtime=>{if(runtime?.localDevelopmentOnly)$("developmentWarning").hidden=false;state.recommendationTrackingEnabled=Boolean(runtime?.recommendationTrackingEnabled);state.recommendationTrackingLocalPreview=Boolean(runtime?.recommendationTrackingLocalPreview);$("recommendationTrackingFilterLabel").hidden=!state.recommendationTrackingEnabled;if(state.recommendationTrackingEnabled&&dashboardQuery.snapshot)void loadRecommendationTracking();}).catch(()=>{});
apiFetch("/api/auth").then(response=>{if(!response.ok)throw new Error(`Authentication status: ${response.status}`);return response.json();}).then(auth=>{const element=$("authStatus");element.hidden=presentation.authentication?.showStatus===false;element.textContent=auth.enabled?(auth.user?.displayName?`Signed in as ${auth.user.displayName}`:"Signed in with Microsoft Entra ID"):"Local access · authentication off";element.classList.toggle("authenticated",Boolean(auth.authenticated));configureSignedInUser(auth);configureBranding(auth);}).catch(()=>{$("authStatus").textContent="Authentication status unavailable";$("signedInUser").hidden=true;});
/** Select a ready snapshot before requesting the active view. */
function loadDashboardDatasets(){
  initialize();
  return startSnapshotDashboard();
}

function initialize(){
  $("reportingActivitySlot").appendChild($("newActivityBar"));
  $("returnToPrimary").addEventListener("click",()=>activateView(primaryView));
  $("dashboardHelp").addEventListener("click",()=>activateView("help"));
  $("printReporting").addEventListener("click",()=>{
    if(state.activeView!=="trend"||!dashboardQuery.reportReady){dashboardStatus("Reporting must finish loading successfully before printing.",true);return;}
    document.body.classList.add("reporting-print");
    window.addEventListener("afterprint",()=>document.body.classList.remove("reporting-print"),{once:true});
    window.print();
  });
  $("exportReportCsv").addEventListener("click",()=>{void exportDashboardCsv("trend","trendManagementComparisonTable");});
  $("recommendationCatalogStatus").value=state.recommendationCatalogStatus;
  $("recommendationCatalogSort").value=state.recommendationCatalogSort;
  for(const key of ["recommendationCatalogStatus","recommendationCatalogSort"])$(key).addEventListener("change",event=>{state[key]=event.target.value;clearSelectedWorkItem();render();});
  $("recommendationWorkspaceFilters").addEventListener("click",event=>{event.stopPropagation();setFilterExpanded(true,true);});
  $("resetRecommendationCatalog").addEventListener("click",()=>{state.recommendationCatalogStatus="Unresolved exposure";state.recommendationCatalogSort="priority";$("recommendationCatalogStatus").value=state.recommendationCatalogStatus;$("recommendationCatalogSort").value=state.recommendationCatalogSort;clearSelectedWorkItem();render();});
  [["severityFilter","severity"],["assetClassFilter","assetClass"],["osTypeFilter","osType"],["subscriptionFilter","subscription"],["teamFilter","team"]].forEach(([id,key])=>$(id).addEventListener("change",event=>{state[key]=event.target.value;render();}));
  $("exposureStatusFilter").addEventListener("change",event=>{state.exposureStatus=event.target.value;render();});
  $("pendingOnlyFilter").addEventListener("click",()=>{state.exposureStatus=state.exposureStatus==="PendingOnly"?"DetectedAndPending":"PendingOnly";$("exposureStatusFilter").value=state.exposureStatus;render();});
  $("hideNonReporting").addEventListener("change",event=>{state.hideNonReporting=event.target.checked;$("reportingDays").disabled=!state.hideNonReporting;render();});
  $("includeInactive").addEventListener("change",event=>{state.includeInactive=event.target.checked;render();});
  $("reportingDays").addEventListener("change",event=>{state.reportingDays=Number(event.target.value);render();});
  $("includeDiscoveredAssets").addEventListener("change",event=>{state.includeDiscoveredOnly=event.target.checked;clearSelectedWorkItem();render();});
  $("recommendationTrackingFilter").addEventListener("change",event=>{state.recommendationTrackingFilter=event.target.value;render();});
  $("searchFilter").addEventListener("input",event=>{state.search=event.target.value.trim().toLowerCase();render();});
  $("newPeriod").addEventListener("change",event=>{state.newPeriod=event.target.value;initializeCustomNewPeriod();$("newPeriodCustom").hidden=state.newPeriod!=="custom";clearSelectedWorkItem();render();});
  $("applyNewPeriodFilter").addEventListener("change",event=>{state.newPeriodFilter=event.target.checked;if(state.newPeriodFilter)state.remediationPeriodFilter=false;clearSelectedWorkItem();render();});
  $("newPeriodStart").addEventListener("change",event=>{state.newPeriodStart=event.target.value;clearSelectedWorkItem();render();});
  $("newPeriodEnd").addEventListener("change",event=>{state.newPeriodEnd=event.target.value;clearSelectedWorkItem();render();});
  $("clearSlaSummary").addEventListener("click",()=>{state.slaSummary={severity:"All",status:""};render();});
  $("toggleNewPeriodFilter").addEventListener("click",()=>{if(state.remediationPeriodFilter){state.remediationPeriodFilter=false;state.newPeriodFilter=false;}else state.newPeriodFilter=!state.newPeriodFilter;$("applyNewPeriodFilter").checked=state.newPeriodFilter;clearSelectedWorkItem();render();});
  document.querySelectorAll(".latest-run-changes-toggle").forEach(input=>input.addEventListener("change",event=>{state.latestRunChangesOnly=event.target.checked;clearSelectedWorkItem();render();}));
  document.querySelectorAll("[data-new-view]").forEach(button=>button.addEventListener("click",()=>{if(button.dataset.findingsMode)findingsList.mode=button.dataset.findingsMode;findingsList.page=0;activateView(button.dataset.newView,{newPeriodFilter:true,remediationPeriodFilter:false});}));
  document.querySelectorAll("[data-fixed-view]").forEach(button=>button.addEventListener("click",()=>{if(button.dataset.findingsMode)findingsList.mode=button.dataset.findingsMode;findingsList.page=0;activateView(button.dataset.fixedView,{remediationPeriodFilter:true,newPeriodFilter:false,exposureStatus:"All"});}));
  $("findingsMode").addEventListener("change",event=>{findingsList.mode=event.target.value;findingsList.page=0;renderFindingsList();});
  $("findingsSearch").addEventListener("input",event=>{state.search=event.target.value.trim().toLowerCase();$("searchFilter").value=event.target.value;clearSelectedWorkItem();render();});
  document.querySelectorAll("[data-findings-page]").forEach(button=>button.addEventListener("click",()=>{const action=button.dataset.findingsPage;findingsList.page=action==="first"?0:action==="last"?Number.MAX_SAFE_INTEGER:findingsList.page+(action==="next"?1:-1);renderFindingsList();}));
  document.querySelectorAll('input[name="recommendationType"]').forEach(input=>input.addEventListener("change",()=>{state.recommendationTypes=new Set([...document.querySelectorAll('input[name="recommendationType"]:checked')].map(item=>item.value));clearSelectedWorkItem();render();}));
  document.querySelectorAll('input[name="assetDomain"]').forEach(input=>input.addEventListener("change",()=>{state.domains=new Set([...document.querySelectorAll('input[name="assetDomain"]:checked')].map(item=>item.value));clearSelectedWorkItem();render();}));
  document.querySelectorAll(".story-nav button[data-view]").forEach(button=>button.addEventListener("click",()=>activateView(button.dataset.view)));
  $("brandLogoButton").addEventListener("click",()=>{if(!$("brandLogoButton").disabled)$("customerLogoInput").click();});
  $("customerLogoInput").addEventListener("change",event=>{const file=event.target.files?.[0];event.target.value="";uploadCustomerLogo(file);});
  $("navToggle").addEventListener("click",()=>setNavigationCollapsed(!document.body.classList.contains("nav-collapsed"),true));
  $("filterToggle").addEventListener("click",()=>setFilterExpanded($("filterBar").hidden,true));
  $("closeFilter").addEventListener("click",()=>{setFilterExpanded(false,true);$("filterToggle").focus();});
  $("statisticsPeriod").addEventListener("change",event=>{state.statisticsPeriod=event.target.value;$("customPeriodFields").hidden=state.statisticsPeriod!=="custom";renderTrend();});
  $("applyStatisticsPeriod").addEventListener("click",renderTrend);
  $("executiveSnapshotPeriod").addEventListener("change",event=>{state.executiveSnapshotPeriod=event.target.value;$("executiveSnapshotCustom").hidden=state.executiveSnapshotPeriod!=="custom";renderExecutiveSnapshot();});
  $("executiveSnapshotSubscription").addEventListener("change",event=>{state.executiveSnapshotSubscription=event.target.value;renderExecutiveSnapshot();});
  $("executiveSnapshotOwner").addEventListener("change",event=>{state.executiveSnapshotOwner=event.target.value;renderExecutiveSnapshot();});
  $("executiveSnapshotUnit").addEventListener("change",event=>{state.executiveSnapshotUnit=event.target.value;renderExecutiveSnapshot();});
  $("applyExecutiveSnapshot").addEventListener("click",()=>{state.executiveSnapshotStart=$("executiveSnapshotStart").value;state.executiveSnapshotEnd=$("executiveSnapshotEnd").value;renderExecutiveSnapshot();});
  for(const view of ["slaDashboard"]){
    $(`${view}ComplianceApply`).addEventListener("click",()=>applyCompliancePeriod(view));
    $(`${view}ComplianceClear`).addEventListener("click",()=>applyCompliancePeriod(view,true));
  }
  $("printExecutiveSnapshot").addEventListener("click",printExecutiveSnapshot);
  $("exportExecutiveSnapshotCsv").addEventListener("click",exportExecutiveSnapshotCsv);
  $("reportingEntity").addEventListener("change",event=>{state.reportingEntity=event.target.value;renderLifecycleReporting();});
  $("reportingBreakdown").addEventListener("change",event=>{state.reportingBreakdown=event.target.value;renderLifecycleReporting();});
  $("reportingChange").addEventListener("change",event=>{state.reportingChange=event.target.value;renderLifecycleReporting();});
  $("machineHistoryPeriod").addEventListener("change",event=>{
    state.machineHistory.period=event.target.value;
    for(const id of ["machineHistoryStart","machineHistoryEnd"])$(id).disabled=event.target.value!=="custom";
  });
  $("applyMachineHistory").addEventListener("click",()=>{
    state.machineHistory={enabled:true,period:$("machineHistoryPeriod").value,start:$("machineHistoryStart").value,end:$("machineHistoryEnd").value};
    if(state.selectedEntity?.type==="machine")void queryDashboardView("detail");
  });
  $("machineCveStatus").addEventListener("change",event=>{
    state.machineCveStatus=event.target.value;
    if(state.selectedEntity?.type==="machine")void queryDashboardView("detail");
  });
  $("exportReportingCsv").addEventListener("click",exportLifecycleCsv);
  $("openWorkflowHelp").addEventListener("click",()=>activateView("help"));
  document.addEventListener("click",event=>{const controls=document.querySelector(".workspace-controls");if(!$("filterBar").hidden&&controls&&!controls.contains(event.target))setFilterExpanded(false,true);});
  document.addEventListener("keydown",event=>{if(event.key==="Escape"&&!$("filterBar").hidden){setFilterExpanded(false,true);$("filterToggle").focus();}});
  $("resetFilters").addEventListener("click",resetFilters);
  $("clearPivot").addEventListener("click",closeDashboardDetail);
  $("pivotPrevious").addEventListener("click",()=>navigateRecommendationDetail(-1));
  $("pivotNext").addEventListener("click",()=>navigateRecommendationDetail(1));
  $("pivotBackdrop").addEventListener("click",closeDashboardDetail);
  $("defenderRemediationLink").addEventListener("click",()=>{const recommendation=state.recommendationsById.get(state.selectedRecommendationId);if(recommendation)copyRecommendationReference(recommendation,"Reference copied. Open Vulnerabilities and paste it into recommendation search.");});
  $("copyRecommendationReference").addEventListener("click",()=>{const recommendation=state.recommendationsById.get(state.selectedRecommendationId);if(recommendation)copyRecommendationReference(recommendation,"Recommendation reference copied.");});
  document.querySelectorAll("[data-tracking-status]").forEach(button=>button.addEventListener("click",()=>updateRecommendationTracking(button.dataset.trackingStatus)));
  $("defenderDeviceLink").addEventListener("click",()=>{const text=$("defenderDeviceLink").dataset.copyText;if(text)navigator.clipboard?.writeText(text);});
  $("closeDialog").addEventListener("click",()=>$("detailDialog").close());
  $("closeMetricHelp").addEventListener("click",()=>$("metricHelpDialog").close());
  document.addEventListener("click",event=>{
    const trigger=event.target.closest?.("[data-help-key]");
    if(!trigger)return;
    event.preventDefault();event.stopPropagation();
    openMetricHelp(trigger.dataset.helpKey);
  },true);
  document.addEventListener("keydown",event=>{
    if((event.key==="Enter"||event.key===" ")&&event.target.closest?.("[data-help-key]"))event.stopPropagation();
  },true);
  if(typeof ResizeObserver!=="undefined"){
    const controls=document.querySelector(".workspace-controls");
    new ResizeObserver(()=>document.documentElement.style.setProperty("--workspace-controls-height",`${controls.getBoundingClientRect().height}px`)).observe(controls);
  }
}

function restorePivotFilters(){
  if(!pivotFilterRestore)return;
  Object.assign(state,pivotFilterRestore);
  pivotFilterRestore=null;
  syncPivotFilterControls();
}

function syncPivotFilterControls(){
  for(const [id,key] of [["severityFilter","severity"],["subscriptionFilter","subscription"],["teamFilter","team"],["exposureStatusFilter","exposureStatus"]])$(id).value=state[key];
  $("applyNewPeriodFilter").checked=state.newPeriodFilter;
}

function activateView(view,pivotFilters=null){
  if(view==="sla")view="slaDashboard";
  if(view==="priority"){view="recommendations";state.recommendationCatalogSort="priority";$("recommendationCatalogSort").value="priority";}
  const section=$(view);if(!section)return;
  if(PRIMARY_VIEWS[view])primaryView=view;
  const button=document.querySelector(`.story-nav button[data-view="${primaryView}"]`);
  const viewChanged=state.activeView!==view;
  if(viewChanged||pivotFilters){
    clearSelectedWorkItem();
    restorePivotFilters();
    if(pivotFilters){
      pivotFilterRestore=Object.fromEntries(Object.keys(pivotFilters).map(key=>[key,state[key]]));
      Object.assign(state,pivotFilters);
      syncPivotFilterControls();
    }
  }
  document.querySelectorAll(".story-nav button,.story").forEach(node=>node.classList.remove("active"));
  button?.classList.add("active");section.classList.add("active");state.activeView=view;
  $("contextualViewBar").hidden=Boolean(PRIMARY_VIEWS[view]);
  $("returnToPrimary").textContent=`Back to ${PRIMARY_VIEWS[primaryView]}`;
  $("contextualViewTitle").textContent={overview:"Vulnerabilities",workstations:"Machines",help:"Dashboard help",executiveSnapshot:"Report preview"}[view]||"";
  $("newActivityBar").hidden=view!=="trend";
  render();
  requestAnimationFrame(()=>window.scrollTo(0,0));
}

function defenderRecommendationUrl(){return DEFENDER_RECOMMENDATIONS_URL;}
function closeDashboardDetail(){clearSelectedWorkItem();render();}
function clearSelectedWorkItem(){
  invalidateDashboardChannel(dashboardQuery.detail);
  dashboardQuery.detailTables.clear();
  updateScopeLoading("detail",false);
  if(!dashboardQuery.main.busy)hideDashboardLoadingNotice();
  state.selectedRecommendationId="";state.detailRecommendationIds=[];state.selectedEntity=null;
  state.selectedCveDialogId="";state.pivotSourceLabel="";
  document.body.classList.remove("pivot-detail-open");
  $("pivotPanel")?.classList.remove("fullscreen-mode");
  if($("pivotBackdrop"))$("pivotBackdrop").hidden=true;
  if($("pivotPanel"))$("pivotPanel").hidden=true;
  $("machineHistoryControls").hidden=true;
  $("machineRemediation").hidden=true;
}
function defenderDeviceUrl(device){const id=String(device.DeviceId||"");return id?`https://security.microsoft.com/machines/${encodeURIComponent(id)}`:"https://security.microsoft.com/machines";}
function copyRecommendationReference(recommendation,message){const text=`${recommendation.RecommendationName}\nRecommendation ID: ${recommendation.RecommendationId}`;navigator.clipboard?.writeText(text).then(()=>{$("pivotActionStatus").textContent=message;}).catch(()=>{$("pivotActionStatus").textContent=`Recommendation ID: ${recommendation.RecommendationId}`;});}
function normalizedCve(value){return String(value||"").trim().toUpperCase();}
function subscriptionLabel(value){const id=String(value),subscription=state.subscriptionInventoryById.get(id);if(!subscription)return id.startsWith("sample-")?id:`${id.slice(0,8)}…`;const stateLabel=subscription.State&&subscription.State!=="Enabled"?` · ${subscription.State}`:"";return `${subscription.SubscriptionName||id} · ${id}${stateLabel}`;}
/** Latest snapshot timestamp represented by the loaded finding data. */
function datasetSnapshotMs(){return state.snapshotTimeMs;}
/** Initialize a useful custom first-observed range from the current snapshot. */
function initializeCustomNewPeriod(){if(state.newPeriod!=="custom"||state.newPeriodStart&&state.newPeriodEnd)return;const end=datasetSnapshotMs();if(!Number.isFinite(end))return;state.newPeriodEnd=new Date(end).toISOString().slice(0,10);state.newPeriodStart=new Date(end-6*86400000).toISOString().slice(0,10);$("newPeriodStart").value=state.newPeriodStart;$("newPeriodEnd").value=state.newPeriodEnd;}
/** Resolve the selected first-observed period against the dataset snapshot. */
function newPeriodRange(){
  const snapshot=datasetSnapshotMs();
  if(!Number.isFinite(snapshot))return null;
  if(state.newPeriod==="runs"){
    const comparison=dashboardQuery.lastResponse?.metadata?.activityComparison;
    if(!comparison?.available)return null;
    return {start:Date.parse(comparison.previousUtc),end:Date.parse(comparison.latestUtc),label:"Vulnerability activity since the previous comparable run",relative:false,exclusiveStart:true};
  }
  if(state.newPeriod==="custom"){
    const start=Date.parse(`${state.newPeriodStart}T00:00:00.000Z`),end=Date.parse(`${state.newPeriodEnd}T23:59:59.999Z`);
    return Number.isFinite(start)&&Number.isFinite(end)&&start<=end?{start,end,label:`Vulnerability activity from ${state.newPeriodStart} through ${state.newPeriodEnd}`,relative:false}:null;
  }
  const days={day:1,week:7,month:30}[state.newPeriod]||1,label={day:"Vulnerability activity in the 24 hours ending at latest collection",week:"Vulnerability activity in the 7 days ending at latest collection",month:"Vulnerability activity in the 30 days ending at latest collection"}[state.newPeriod]||"Vulnerability activity in the 24 hours ending at latest collection";
  return {start:snapshot-days*86400000,end:snapshot,label,relative:true};
}
/** Format a shared recommendation workflow state. */
function recommendationTrackingLabel(status){return{All:"All work statuses",NeedsAttention:"Needs attention",InProgress:"In progress",NeedsReassignment:"Needs reassignment",ReadyForValidation:"Marked fixed · awaiting collection",Confirmed:"Confirmed fixed",StillDetected:"Still detected after validation",Untracked:"Untracked / not started"}[status]||"Untracked / not started";}
function taskDueLabel(status){return{CompletedWithinDueDate:"Completed by due date",CompletedOutsideDueDate:"Completed after due date",OpenWithinDueDate:"Open before due date",OpenOutsideDueDate:"Open overdue",Canceled:"Canceled",Unknown:"Unknown"}[status]||status;}

function resetFilters(){pivotFilterRestore=null;state.origin="Both";state.severity="All";state.exposureStatus="DetectedAndPending";state.assetClass="All";state.osType="All";state.subscription="All";state.hideNonReporting=Boolean(filterConfig.defaultHideNonReporting);state.includeInactive=false;$("includeInactive").checked=false;state.reportingDays=DEFAULT_REPORTING_DAYS;state.includeDiscoveredOnly=Boolean(filterConfig.defaultIncludeDiscoveredOnly);state.team="All";state.search="";state.newPeriod="day";state.newPeriodFilter=false;state.remediationPeriodFilter=false;state.latestRunChangesOnly=false;state.newPeriodStart="";state.newPeriodEnd="";state.recommendationTrackingFilter="All";state.recommendationTypes=new Set(DEFAULT_RECOMMENDATION_TYPES);state.domains=new Set(DEFAULT_DOMAINS);clearSelectedWorkItem();$("severityFilter").value="All";$("exposureStatusFilter").value="DetectedAndPending";$("assetClassFilter").value="All";$("osTypeFilter").value="All";$("subscriptionFilter").value="All";$("hideNonReporting").checked=state.hideNonReporting;$("reportingDays").value=String(state.reportingDays);$("reportingDays").disabled=!state.hideNonReporting;$("includeDiscoveredAssets").checked=state.includeDiscoveredOnly;$("teamFilter").value="All";$("recommendationTrackingFilter").value="All";$("searchFilter").value="";$("newPeriod").value="day";$("applyNewPeriodFilter").checked=false;$("newPeriodCustom").hidden=true;$("newPeriodStart").value="";$("newPeriodEnd").value="";document.querySelectorAll(".latest-run-changes-toggle").forEach(input=>input.checked=false);document.querySelectorAll('input[name="recommendationType"]').forEach(input=>input.checked=state.recommendationTypes.has(input.value));document.querySelectorAll('input[name="assetDomain"]').forEach(input=>input.checked=state.domains.has(input.value));render();}
function activeFilterItems(classLabels,subscriptionScope,typeScope,domainScope){const items=[];if(state.severity!=="All")items.push(["Severity",state.severity]);if(state.exposureStatus!=="DetectedAndPending")items.push(["Exposure",{DetectedOnly:"Open on active devices",PendingOnly:"Open on inactive devices",ConfirmedFixed:"Fixed only",All:"Open and fixed"}[state.exposureStatus]||state.exposureStatus]);if(state.includeInactive)items.push(["Inactive devices","Included"]);if(state.assetClass!=="All")items.push(["Asset",classLabels[state.assetClass]]);if(state.osType!=="All")items.push(["OS Type",state.osType]);if(state.subscription!=="All")items.push(["Subscription",subscriptionScope]);if(state.hideNonReporting)items.push(["Reporting",`Within ${state.reportingDays} days`]);if(state.team!=="All")items.push(["Queue",state.team]);if(state.newPeriodFilter)items.push(["First observed",newPeriodRange()?.label||"Invalid custom range"]);if(state.remediationPeriodFilter)items.push(["Remediation observed",newPeriodRange()?.label||"Invalid custom range"]);if(state.latestRunChangesOnly)items.push(["Run changes","New, reopened, or fixed since previous run"]);if(state.recommendationTrackingEnabled&&state.recommendationTrackingFilter!=="All")items.push(["Work status",recommendationTrackingLabel(state.recommendationTrackingFilter)]);if(state.recommendationTypes.size!==2)items.push(["Type",typeScope]);if(state.domains.size!==5)items.push(["Domains",domainScope]);if(state.search)items.push(["Search",state.search]);return items;}
function removeWorkspaceFilter(label){
  const fields={
    Severity:["severity","severityFilter","All"],Exposure:["exposureStatus","exposureStatusFilter","DetectedAndPending"],
    Asset:["assetClass","assetClassFilter","All"],"OS Type":["osType","osTypeFilter","All"],
    Subscription:["subscription","subscriptionFilter","All"],Queue:["team","teamFilter","All"],
    Search:["search","searchFilter",""],"Work status":["recommendationTrackingFilter","recommendationTrackingFilter","All"],
  };
  if(fields[label]){
    const [key,id,value]=fields[label];state[key]=value;$(id).value=value;
  }else if(label==="Reporting"){
    state.hideNonReporting=false;$("hideNonReporting").checked=false;$("reportingDays").disabled=true;
  }else if(label==="Inactive devices"){
    state.includeInactive=false;$("includeInactive").checked=false;
  }else if(label==="First observed")state.newPeriodFilter=false;
  else if(label==="Remediation observed")state.remediationPeriodFilter=false;
  else if(label==="Run changes")state.latestRunChangesOnly=false;
  else if(label==="Type"||label==="Domains"){
    const type=label==="Type",values=type?["Vulnerability","Misconfiguration"]:["Devices","Cloud","SaaS Apps","Identities","Data"];
    state[type?"recommendationTypes":"domains"]=new Set(values);
    document.querySelectorAll(`input[name="${type?"recommendationType":"assetDomain"}"]`).forEach(input=>input.checked=values.includes(input.value));
  }
  render();
}
function renderScope(){const classLabels={All:"All asset classifications",AzureCloud:"Azure / Cloud",TraditionalIT:"Traditional IT",Unknown:"Unknown classification"},subscriptionScope=state.subscription==="All"?"All subscriptions":state.subscription==="NoSubscription"?"No subscription":`Subscription ${subscriptionLabel(state.subscription)}`,typeScope=state.recommendationTypes.size===2?"All recommendation types":[...state.recommendationTypes].join(" + ")||"No recommendation types",domainScope=state.domains.size===5?"All asset domains":[...state.domains].join(" + ")||"No asset domains",parts=[state.severity==="All"?"All severities":state.severity,classLabels[state.assetClass],subscriptionScope],chips=activeFilterItems(classLabels,subscriptionScope,typeScope,domainScope);if(state.hideNonReporting)parts.push(`Reported within ${state.reportingDays} days`);if(state.team!=="All")parts.push(state.team);if(state.search)parts.push(`Search: “${state.search}”`);$("scopeSummary").textContent=parts.join(" · ");$("severityFilter").value=state.severity;$("activeFilterChips").innerHTML=chips.length?chips.map(([label,value])=>`<button type="button" data-remove-filter="${esc(label)}" aria-label="Remove ${esc(label)} filter: ${esc(value)}"><b>${esc(label)}</b>${esc(value)} <i aria-hidden="true">&times;</i></button>`).join(""):`<span class="empty"><b>Filters</b>None applied</span>`;$("activeFilterChips").querySelectorAll("[data-remove-filter]").forEach(button=>button.addEventListener("click",()=>removeWorkspaceFilter(button.dataset.removeFilter)));const bar=$("scopeBar");bar.classList.remove("scope-updated");requestAnimationFrame(()=>bar.classList.add("scope-updated"));}

const METRIC_HELP=new Map(Object.entries({
  "Machine vulnerability history":"Dated additions, fixes, and returned CVEs on the selected machine. Added means first seen on the machine. A CVE is fixed on a machine only when none of its affected software on that machine is still detected. A CVE that comes back starts a new episode with a new SLA clock. Dates use UTC. History before retained evidence is unavailable.",
  "Distinct CVEs added":"Different CVEs first observed on this machine during the selected history period. Additional software products or versions for an already unresolved CVE do not add another vulnerability.",
  "Distinct CVEs reopened":"Different CVEs detected again on a machine after they were fixed, during the selected history period. A returned CVE starts a new episode with a new SLA clock. Added, fixed, and reopened counts are separate and can overlap.",
  "Distinct active CVEs":"Different CVE IDs with at least one current detection in this filtered snapshot. Each CVE is counted once, even across many devices, products, or versions. A recommendation's total combines CVEs across all its matching devices; an individual device can have fewer because devices do not all have the same CVEs. Pending evidence is excluded.",
  "Workloads with detections":"Distinct workloads with at least one open vulnerability in the current filters. A workload is a device unless configured VM scale-set or workload grouping combines multiple instances.",
  "Related recommendations":"Distinct recommendations linked to this item's vulnerability evidence in the current filters. One machine can have several recommendations, and one recommendation can address many CVEs on many machines. Select a related recommendation row to open its details.",
  "Machines with detections":"Distinct devices with at least one open vulnerability in the current filters.",
  "Confirmed machine/CVE fixes":"Machine/CVE pairs fixed in the selected period: the CVE is no longer detected in any affected software on that machine. Each CVE counts once per machine.",
  "Summary":"A snapshot of open CVEs and affected machines in the selected workspace scope. CVEs and machines are counted separately, once each. Open risk is assessed at the snapshot time; fixes refer to the displayed reporting period.",
  "Recommendations":"Distinct remediation-action IDs in the filtered catalog, counted once each. One recommendation can address several CVEs on many machines. Its dashboard work status is a manually selected coordination state; exposure, progress, and SLA risk are calculated from collection evidence. Marking an action In progress or Fixed does not itself clear any vulnerability.",
  "Active":"Recommendations whose retained Defender catalog status is Active. This is not a count of active machines, a dashboard In progress marker, a confirmed fix, or an SLA compliance assessment.",
  "Critical recommendations":"Distinct recommendations classified Critical in the filtered catalog. A recommendation may cover several CVEs and machines; not every linked CVE or machine necessarily has this severity.",
  "High recommendations":"Distinct recommendations classified High in the filtered catalog. This counts remediation actions, not CVEs or affected machines, and is separate from dashboard work status.",
  "Remediation started":"Distinct recommendations whose retained Defender evidence indicates remediation was triggered. This does not itself establish that vulnerabilities disappeared, that a fix was confirmed, or that an SLA deadline was met.",
  "Status and progress":"Every machine/CVE pair is in one of four states: Open – within SLA, Open – past SLA, Fixed – within SLA, or Fixed – past SLA. Pairs without a known deadline show No SLA deadline. A machine or CVE is Open while any of its pairs is open, and Fixed only when all are fixed. Dashboard work status is separate coordination and does not change these states.",
  "Progress status":"Open means at least one machine/CVE pair for this item is still open in scope. Fixed means every pair for this item is fixed. A fix on one software item or one machine does not make a CVE fixed.",
  "Fully resolved":"Fixed during the reporting period with nothing left open for this item in the selected scope. A machine has no open CVEs; a CVE has no open machines.",
  "Fully cleared":"A distinct CVE or machine was fixed completely during the displayed period: a CVE has no open machine left in scope; a machine has no open CVE left in scope.",
  "Fully remediated":"This recommendation had a fix during the reporting period and has nothing left open in the selected scope. Other recommendations or vulnerabilities can still affect the same machines.",
  "SLA risk status":"The SLA state at the selected snapshot. Open – past SLA if any open pair is past its deadline; otherwise Open – no SLA deadline if a deadline is missing; otherwise Open – within SLA. Fixed items show Fixed or the pair's fixed state.",
  "Current SLA status":"Distinct CVEs and machines assessed separately. Open equals Open – within SLA plus Open – past SLA plus No SLA deadline. Fully cleared counts complete fixes in the displayed reporting period.",
  "Unresolved":"Distinct CVEs or machines with any open machine/CVE pair in the selected scope. Each entity is counted once. This equals Open – within SLA plus Open – past SLA plus No SLA deadline. Open pairs on inactive devices are included only when Include inactive devices is on.",
  "Not yet due":"Open, and its SLA deadline has not passed at the assessment time. This is not a fix.",
  "Overdue":"Open, and at least one vulnerability is past its SLA deadline at the assessment time. A distinct CVE or machine is counted once even if several of its vulnerabilities are overdue.",
  "Deadline unknown":"Open with no known SLA deadline and no known overdue vulnerability. It is not counted as within SLA.",
  "Unknown SLA":"A required SLA deadline is missing or cannot be assessed from retained evidence. Unknown is not a compliant or successful result. Known overdue or late evidence takes precedence over a missing deadline.",
  "No remaining risk":"No unresolved exposure remains for this item within the selected filters. This does not certify the whole tenant or other CVEs outside this scope, and it does not by itself establish an on-time completion.",
  "Cleared on time":"Fixed during the displayed period, and every machine/CVE pair was fixed on or before its SLA deadline.",
  "Cleared late":"Fixed during the displayed period, but at least one machine/CVE pair was fixed after its SLA deadline.",
  "Clearance deadline unknown":"Fixed during the period, but a deadline is missing and no late fix takes precedence. It is excluded from the on-time percentage.",
  "Confirmed on-time %":"Fixed – within SLA divided by Fixed – within SLA plus Fixed – past SLA, in the unit shown. Fixes without a known deadline are excluded. Open items are not included.",
  "Completed within SLA":"Fixes on or before their SLA deadlines. In a machine row these are its fixed CVEs; in a CVE row they are its fixed machines.",
  "Completed late":"Fixes after their SLA deadlines, in the row's unit: CVEs on a machine or machines for a CVE.",
  "Completed, unknown SLA":"Fixes without a known SLA deadline. They are excluded from the on-time percentage.",
  "Open within SLA %":"Open vulnerabilities with known deadlines that are not yet past due, divided by all open vulnerabilities with known deadlines in this row. Unknown deadlines are excluded.",
  "Open within deadline":"Open vulnerabilities in this row whose deadlines have not passed.",
  "Open, unknown deadline":"Open vulnerabilities in this row without a known SLA deadline. They are excluded from deadline-based percentages.",
  "Sla Due Utc":"The SLA deadline for this machine/CVE pair: first seen on the machine plus the policy days for its severity (config/sla-policies.json). It is not the CVE publication date or a task due date.",
  "Machines with open risk":"Distinct machines with any open in-scope vulnerability. Each machine counts once, regardless of software versions or the number of CVEs.",
  "Open vulnerabilities (unique CVEs)":"Distinct CVE IDs open on at least one in-scope machine. Each CVE counts once across all machines and software versions.",
  "Open CVEs":"Distinct CVEs open in the selected scope and reporting period. A CVE counts once even when many machines or software versions are affected. A fix on some machines does not remove it from this total.",
  "CVEs remaining":"Distinct CVEs still open on this machine or recommendation in the selected scope.",
  "Open recommendations":"Distinct recommendations with unresolved in-scope exposure. One recommendation may relate to many CVEs and machines. This is a count of remediation actions, not a vulnerability total.",
  "Affected machines":"Distinct machines with matching vulnerability evidence in the displayed scope. The same machine can be linked to several CVEs or recommendations but appears once in this item's machine count.",
  "Machines with overdue risk":"Distinct machines with at least one unresolved vulnerability past its SLA deadline. This is a subset of Machines with open risk, not an additional machine total.",
  "CVEs with overdue risk":"Distinct CVEs with at least one unresolved, overdue exposure on an in-scope machine. This is a subset of open CVEs; multiple overdue machines do not multiply the CVE count.",
  "Dashboard work status":"Shared manual coordination state attached to a recommendation ID. In progress records that work is being coordinated; Fixed, awaiting collection requests validation by later collection evidence. These actions do not patch a machine, change Defender, stop the SLA clock, or prove resolution.",
  "In progress":"Someone marked this recommendation as being worked on in the dashboard. This does not change Defender, remove exposure, pause the SLA clock, or establish a confirmed fix. Its calculated progress can still be Still open or Overdue.",
  "Marked fixed · awaiting collection":"Someone marked the recommendation fixed in the dashboard, but collection evidence has not yet validated that claim. It remains separate from confirmed remediation and does not stop or reset its SLA clock.",
  "Confirmed fixed":"A newer collection after work was marked found no active detections for this recommendation. This workflow status is separate from qualified lifecycle confirmation and entity-level SLA calculations; pending verification can still require evidence, and unrelated CVEs or recommendations may remain unresolved.",
  "Still detected after validation":"A collection after the dashboard's fixed marker still found active exposure for this recommendation. The manual fixed claim has not been validated; calculated risk and SLA continue to follow the evidence.",
  "Needs reassignment":"At least seven days have elapsed since the work marker and a newer collection still has active detections for this recommendation. This is an age-based coordination warning, not evidence that ownership changed, a remediation result, or a new SLA deadline.",
  "Needs attention":"The workflow filter includes recommendations not marked Fixed, awaiting collection or Confirmed fixed. It includes untracked work, In progress, still-detected work, and reassignment warnings. It does not mean every item is overdue.",
  "Untracked / not started":"No active manual work marker exists for this recommendation. This does not mean there is no exposure or that work has not occurred outside this dashboard.",
  "Working here?":"Indicates dashboard coordination for a recommendation. Work status is independent of evidence-based progress and SLA deadlines; marking work does not perform remediation.",
  "Defender remediation started":"Whether the retained Defender recommendation evidence indicates remediation work has started. This is separate from dashboard work status and does not itself prove exposure was removed.",
  "Severity":"For management totals, a machine or CVE appears once at its highest open in-scope severity. In a fixed row, severity comes from the retained evidence.",
  "Recommendation severity":"The highest relevant severity used to rank this recommendation's exposure. It does not mean every linked CVE or affected machine has that severity.",
  "Known exploit":"Whether retained evidence reports a known exploit for the item. Unknown is not the same as No. The applicable retained SLA policy may use exploit evidence when selecting the deadline.",
  "Period":"The reporting window for fixes, in UTC. Open counts are reconstructed at the period end, capped at the pinned snapshot.",
  "Open at period end":"Distinct entities open at the end of the displayed reporting period, capped at the pinned snapshot. This is an end-of-period backlog, not the number of new vulnerabilities during the period.",
  "Range":"The inclusive UTC dates of the reporting period. The same entity can have had fixes during the period and still be open at its end.",
  "Coverage":"Whether retained observations cover the requested reporting period. Missing or partial history is not proof of zero risk or zero remediation. Full calendar comparisons require coverage from the beginning of each completed period.",
  "Waiting for data":"The evidence or known-deadline completions needed for this assessment are unavailable. This is not zero, 0% compliance, or proof that nothing happened.",
  "History coverage":"The span of retained collection observations available for reconstructing earlier status. It is not the CVE publication history. Incomplete completed weeks or months show Waiting for data instead of a misleading zero.",
  "Week over week":"The last completed Monday-through-Sunday UTC week compared with the completed week before it. The current partial week is excluded. Differences are distinct entity counts, not percentage-point changes.",
  "Month over month":"The last completed calendar month compared with the completed month before it, in UTC. The current partial month is excluded. Full retained history is required for both periods.",
  "Endpoint device inventory":"Distinct Defender endpoint inventory records, not all Azure resources. Discovered-only or non-onboarded devices do not establish assessed vulnerability coverage. Inventory counts and machines with open risk answer different questions.",
  "Vulnerability coverage":"Whether vulnerability evidence is available for this endpoint. Not assessed is not proof that the machine is secure or that it has zero CVEs; inventory-only devices can lack assessment evidence.",
  "CVEs confirmed fixed on this machine":"Distinct CVEs fixed in all affected software on this machine during the reporting period. Other CVEs can remain open.",
  "Machines with this CVE confirmed fixed":"Distinct machines where this CVE was fixed during the reporting period. The CVE can remain open on other machines.",
  "Distinct CVEs fixed":"Different CVEs fixed on this machine during the selected history period: none of the CVE's affected software on the machine is still detected. A CVE can come back later as a new episode.",
  "Open":"Still detected in scope: a CVE on at least one machine, or a machine with at least one CVE. A fix on some software or some machines does not change this until nothing is left open.",
  "Fixed":"Nothing is left open for this item in scope: none of its affected software is still detected.",
  "Open – within SLA":"Still open, and the SLA deadline (first seen on the machine plus the policy days for the severity) has not passed.",
  "Open – past SLA":"Still open after the SLA deadline (first seen on the machine plus the policy days for the severity).",
  "Fixed – within SLA":"Fixed on or before the SLA deadline: none of the affected software is still detected.",
  "Fixed – past SLA":"Fixed after the SLA deadline: the last affected software was removed late.",
  "No SLA deadline":"No known SLA deadline, for example because the severity is missing. These are excluded from SLA percentages.",
  "Open – no SLA deadline":"Still open with no known SLA deadline, for example because the severity is missing. Excluded from SLA percentages.",
  "Fixed – no SLA deadline":"Fixed, but with no known SLA deadline, for example because the severity is missing. Excluded from SLA percentages.",
  "Open on inactive devices":"Open machine/CVE pairs on devices not seen by Defender for 7 days, or not detected in the latest collection. They are hidden unless Include inactive devices is on, and are never counted as fixed.",
  "Inactive device":"Yes when the item has open vulnerabilities on a device not seen for 7 days. Such pairs stay open and are shown only when Include inactive devices is on.",
  "SLA gauge":"Per severity, the share of machine/CVE pairs that are within SLA: open pairs not yet past their deadline plus pairs fixed on or before their deadline, divided by all pairs with a known deadline. Fixed pairs count when they were fixed in the selected period. N/A means there is nothing to assess.",
  "Open vs fixed over time":"Daily machine/CVE pairs for the last 90 days: Open is how many pairs were open at the end of each day; Fixed is how many pairs were fully fixed that day. A pair opens when first seen and is fixed only when none of its software is still detected. Inactive devices are included only when Include inactive devices is on.",
  "CVEs on inactive devices":"Different CVE IDs that are open only on devices not seen for 7 days, or not detected in the latest collection. They stay open and never count as fixed. The same CVE can also be active on another device, so active and inactive CVE counts can overlap.",
  "Exposure instances on inactive devices":"Software/version evidence rows that are open on inactive devices. They stay open and never count as fixed.",
  "Include inactive devices":"Off by default. When on, open vulnerabilities on devices not seen for 7 days are added to the open counts. Inactive devices never count as fixed.",
  "CVEs fixed":"Distinct CVEs fixed on this machine: none of their affected software is still detected.",
}).map(([label,description])=>[label.toLowerCase(),description]));
function metricHelp(label){
  const normalized=String(label||"").trim().toLowerCase(),direct=METRIC_HELP.get(normalized);
  if(direct)return direct;
  if(normalized==="fully resolved in scope"||normalized==="fixed (fully cleared) in scope")return METRIC_HELP.get("fully resolved");
  if(/^(machines|cves|recommendations) fully resolved(?: in scope)?$/.test(normalized))return METRIC_HELP.get("fully resolved");
  if(/^(machines|cves) fully cleared(?: this month)?$/.test(normalized))return METRIC_HELP.get("fully cleared");
  return"";
}
function metricHelpButton(label,key=label){const help=metricHelp(key);return help?` <button type="button" class="metric-help-button" data-help-key="${esc(key)}" aria-label="Explain ${esc(label)}" aria-haspopup="dialog" title="${esc(help)}">?</button>`:"";}
function metricLabel(label,key=label){return esc(label)+metricHelpButton(label,key);}
function openMetricHelp(label){
  const description=metricHelp(label);
  if(!description)throw new Error(`No dashboard explanation is defined for ${label}.`);
  $("metricHelpTitle").textContent=label;
  $("metricHelpText").textContent=description;
  if(!$("metricHelpDialog").open)$("metricHelpDialog").showModal();
}
function cards(id,items,hint="Current filter context",actions=[]){
  const links=[];
  $(id).innerHTML=items.map(([value,label,itemHint,table],index)=>{
    const action=actions[index],target=table||action?.table,detail=itemHint??(action?"Click to inspect; click again to show all":hint),help=metricHelp(label),text=typeof value==="number"?fmt(value):esc(value);
    if(target)links.push({table:target,action});
    const selected=action&&state.managementMetric?.table===target&&state.managementMetric.status===action.status;
    return `<div class="metric"${help?` title="${esc(help)}"`:""}><span class="label${help?" metric-help":""}">${metricLabel(label)}</span>${target?`<button type="button" class="value metric-drilldown" data-metric-table="${esc(target)}" aria-label="View ${esc(label)}"${action?` aria-pressed="${Boolean(selected)}"`:""}>${text}</button>`:`<strong class="value">${text}</strong>`}${detail?`<span class="hint">${esc(detail)}</span>`:""}</div>`;
  }).join("");
  $(id).querySelectorAll("[data-metric-table]").forEach((button,index)=>button.addEventListener("click",()=>{
    const {action,table:target}=links[index];
    if(action){
      state.managementMetric=state.managementMetric?.table===target&&state.managementMetric.status===action.status?null:{...action,view:state.activeView};
      render();
      return;
    }
    const table=$(button.dataset.metricTable);
    if(table){table.scrollIntoView({behavior:"smooth",block:"center"});table.setAttribute("tabindex","-1");table.focus({preventScroll:true});}
  }));
}
function headerLabel(column){const labels={InactiveDevice:"Inactive device",ConfirmedMachineCveFixes:"Machine/CVE fixes",OpenSLAWithinRate:"Open within SLA %",OpenMachineCveWithinSLA:"Open within SLA %",OpenWithinSLA:"Open within deadline",UnknownOpenSLA:"Open, unknown deadline",SLACompliance:"Confirmed on-time %",MachineCveSLACompliance:"Confirmed machine/CVE on-time %",FixedCVEs:"CVEs confirmed fixed on this machine",FixedMachines:"Machines with this CVE confirmed fixed",CompletedWithinSLA:"Completed within SLA",CompletedLate:"Completed late",CompletedUnknownSLA:"Completed, unknown SLA",OverdueOutcomes:"Overdue machine/CVE outcomes",ExecutiveStatus:"Executive SLA status",OpenCVEs:"CVEs remaining",CVEsOpen:"Open CVEs",CVEsImproved:"CVEs improved",CVEsFullyResolved:"CVEs fully resolved",MachinesOpen:"Machines with open risk",MachinesImproved:"Machines improved",MachinesFullyResolved:"Machines fully resolved",RecommendationsOpen:"Open recommendations",SlaStatus:"SLA risk status",PendingEvidence:"Awaiting verification",OSPlatform:"OS Type",OSVersion:"OS Version",OSMetadataSource:"OS metadata source",OpenFindings:"Active exposure instances",PendingFindings:"Pending exposure instances",EvidenceRecommendations:"Related recommendations",DetectedMachines:"Machines with detections",DetectedCVEs:"Distinct active CVEs",PendingCVEs:"CVEs with pending evidence",EvidenceRows:"Evidence rows",WorkAction:"Working here?",RemediationStarted:"Defender remediation started",TrackingStatus:"Dashboard work status",TrackingUpdatedBy:"Updated by",TrackingUpdatedUtc:"Updated UTC",SeverityScore:"Defender severity score",FixedWithinSLA:"Remediation observed within SLA",FixedOutsideSLA:"Remediation observed outside SLA",PendingVerification:"Pending verification",OpenOutsideSLA:"Detected findings overdue"};return labels[column]||column.replace(/([A-Z])/g," $1").trim().replace(/\bS L A\b/g,"SLA").replace(/\bC V E\b/g,"CVE").replace(/\bU T C\b/g,"UTC").replace(/\bI D\b/g,"ID");}
/** Render compact work status beneath a recommendation name. */
function recommendationWorkStatus(row){if(!state.recommendationTrackingEnabled||!Object.hasOwn(row,"TrackingStatus"))return"";const status=row.TrackingStatus||"Untracked",details=[row.TrackingUpdatedBy&&row.TrackingUpdatedBy!=="—"?row.TrackingUpdatedBy:"",row.TrackingUpdatedUtc&&row.TrackingUpdatedUtc!=="—"?row.TrackingUpdatedUtc:""].filter(Boolean).join(" · ");return`<span class="recommendation-work-status"><span class="tracking-status ${esc(status)}">${metricLabel(recommendationTrackingLabel(status))}</span>${details?`<small>${esc(details)}</small>`:""}</span>`;}
function explainedCell(column,value,row){
  const content=cell(column,value,row);
  if(!["ProgressStatus","SlaStatus","TrackingStatus","VulnerabilityCoverage"].includes(column))return content;
  const label=column==="TrackingStatus"?recommendationTrackingLabel(value):column==="VulnerabilityCoverage"?"Vulnerability coverage":String(value||"");
  return content+metricHelpButton(label);
}
function table(id,columns,rows,onClick=false){
  const element=$(id),help=column=>{const description=metricHelp(headerLabel(column));return description?` title="${esc(description)}"`:"";};
  const labels={RecommendationSeverity:"Criticality",OverdueCves:"Overdue CVEs",CVEsOverdue:"Overdue CVEs",CveCount:"Distinct CVEs"};
  element.innerHTML=`<thead><tr>${columns.map(column=>`<th${help(column)}>${metricLabel(labels[column]||headerLabel(column),headerLabel(column))}</th>`).join("")}</tr></thead><tbody>${rows.map((row,index)=>`<tr data-index="${index}">${columns.map(column=>`<td${help(column)}>${explainedCell(column,displayDateTime(column,row[column]),row)}</td>`).join("")}</tr>`).join("")}</tbody>`;
  element.querySelectorAll("a").forEach(link=>link.addEventListener("click",event=>{event.stopPropagation();if(link.classList.contains("recommendation-handoff")){const recommendation=rows[Number(link.closest("tr").dataset.index)];navigator.clipboard?.writeText(`${recommendation.RecommendationName}\nRecommendation ID: ${recommendation.RecommendationId}`).catch(()=>{dashboardStatus(`Copy unavailable. Search Defender for recommendation ${recommendation.RecommendationId}.`);});}}));
  if(onClick){
    const handler=typeof onClick==="function"?onClick:showDetail;
    element.querySelectorAll("tbody tr").forEach((tr,index)=>{
      tr.tabIndex=0;
      tr.addEventListener("click",event=>{if(!event.target.closest?.("[data-help-key]"))handler(rows[index]);});
      tr.addEventListener("keydown",event=>{if(event.target.closest?.("[data-help-key]"))return;if(event.key==="Enter"||event.key===" "){event.preventDefault();handler(rows[index]);}});
    });
  }
}
function cell(column,value,row){if(["CvssScore","KnownExploit","PublicExploitAvailable","VerifiedExploitAvailable","ExploitKitAvailable"].includes(column)&&value==null)return"Unknown";if(column==="CveMetadataStatus")return`<span class="pill">${esc(value==="Unavailable"?"Details unavailable":value||"Available")}</span>`;if(["OpenFindings","PendingFindings","Critical","High","Medium","Low"].includes(column)&&row.VulnerabilityCoverage==="Not assessed")return"—";if(column==="FindingStatus"){const description=findingLifecycleDescription(value);return`<span class="lifecycle-status ${esc(value)} lifecycle-tooltip" tabindex="0" data-tooltip="${esc(description)}" aria-label="${esc(`${findingLifecycleLabel(value)}. ${description}`)}">${esc(findingLifecycleLabel(value))}</span>`;}if(column==="SlaEvidenceStatus")return`<span class="lifecycle-status ${esc(value)}">${esc(String(value||"Unknown").replaceAll(/([a-z])([A-Z])/g,"$1 $2"))}</span>`;if(column==="ExposureStatus")return`<span class="lifecycle-status ${String(value).startsWith("Pending")?"PendingConfirmation":"Open"}">${esc(value)}</span>`;if(column==="VulnerabilityCoverage")return`<span class="pill">${esc(value)}</span>`;if(column==="CveId"&&normalizedCve(value))return`<button class="cve-link" type="button" title="View CVE description and evidence">${esc(value)}</button>`;if(row.TrendPoint&&(column==="New"||column==="Fixed"))return `<button class="delta-link" data-change="${column}" type="button">${fmt(value)}</button>`;if(row.SlaSeverityPoint&&column==="Severity")return `<button class="sla-severity-link severity ${esc(value)}" data-severity="${esc(value)}" type="button" title="View ${esc(value)} recommendations fixed within and outside SLA">${esc(value)}</button>`;if(column==="TaskDueStatus")return `<span class="task-status ${esc(value)}">${esc(taskDueLabel(value))}</span>`;if(column==="TrackingStatus")return `<span class="tracking-status ${esc(value)}">${esc(recommendationTrackingLabel(value))}</span>`;if(column==="RecommendationName"){const name=row.DataOrigin==="Live"&&!row.SuppressRecommendationHandoff?`<a class="table-link recommendation-handoff" href="${esc(defenderRecommendationUrl(row))}" target="_blank" rel="noopener" title="Opens Exposure Recommendations and copies this recommendation reference">${esc(value)}</a>`:`<span>${esc(value)}</span>`;return`<div class="recommendation-name-cell"><span class="recommendation-name-main">${name}</span>${recommendationWorkStatus(row)}</div>`;}if(column==="Severity"||column==="RecommendationSeverity")return `<span class="severity ${esc(value)}">${esc(value)}</span>`;if(["RecommendedAction","VulnerabilityMix","FixImpact"].includes(column))return `<span class="impact-text">${esc(value)}</span>`;if(column==="PriorityScore"||column==="SeverityScore")return `<span class="score">${esc(value)}</span>`;if(typeof value==="boolean"||value==="True"||value==="False")return `<span class="pill">${truthy(value)?"Yes":"No"}</span>`;if(column.endsWith("Percent"))return `<strong>${esc(value)}%</strong>`;return esc(value);}
/** Reload shared recommendation workflow state. */
async function loadRecommendationTracking(){try{if(!dashboardQuery.snapshot)return false;const response=await apiFetch(`/api/recommendation-tracking?snapshotId=${encodeURIComponent(dashboardQuery.snapshot.snapshotId)}`);if(response.status===409){expireDashboardSnapshot();return false;}if(!response.ok)throw new Error(`Tracking request failed: ${response.status}`);const payload=await response.json();state.recommendationTracking=new Map((payload.items||[]).map(row=>[String(row.recommendationId),row]));renderRecommendationTrackingStatus();return true;}catch(error){$("recommendationTrackingStatus").textContent=`Tracking unavailable: ${error.message}`;dashboardStatus(`Tracking unavailable: ${error.message}`);return false;}}
/** Save a shared recommendation workflow action. */
async function updateRecommendationTracking(status,recommendationId=state.selectedRecommendationId){const recommendation=state.recommendationsById.get(recommendationId);if(!dashboardQuery.snapshot||dashboardQuery.expired||!recommendation||(recommendation.DataOrigin!=="Live"&&!state.recommendationTrackingLocalPreview))return false;const statusElement=$("recommendationTrackingStatus");statusElement.textContent="Saving dashboard work status…";try{const response=await apiFetch(`/api/recommendation-tracking?snapshotId=${encodeURIComponent(dashboardQuery.snapshot.snapshotId)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({recommendationId,status})});if(response.status===409){expireDashboardSnapshot();return false;}if(!response.ok)throw new Error(`Update failed: ${response.status}`);if(!await refreshRecommendationTracking()){statusElement.textContent="Dashboard work status was saved, but refreshing it failed. Retry the dashboard query to read the saved status.";return false;}return true;}catch(error){statusElement.textContent=`Dashboard work-status update failed: ${error.message}`;return false;}}
function renderRecommendationTrackingStatus(){
  if(state.selectedEntity?.type!=="recommendation")return;
  const tracking=state.recommendationTracking.get(state.selectedRecommendationId)||{};
  $("recommendationTrackingStatus").textContent=`${recommendationTrackingLabel(tracking.effectiveStatus||tracking.status||"Untracked")}${tracking.updatedByDisplayName?` · ${tracking.updatedByDisplayName}`:""}${tracking.updatedUtc?` · ${formatUtc(tracking.updatedUtc)}`:""}`;
}
/** Move through recommendations in the current filtered scope. */
function navigateRecommendationDetail(offset){const index=state.detailRecommendationIds.indexOf(state.selectedRecommendationId),id=state.detailRecommendationIds[index+offset];if(!id)return;state.selectedRecommendationId=id;state.selectedEntity={type:"recommendation",id};renderPivot();$("pivotPanel").scrollTo({top:0,behavior:"smooth"});}
function setPivotShell(kind,title,summary,showRecommendationActions=false,recommendation=null){const panel=$("pivotPanel"),recommendationDetail=kind==="Selected: Recommendation",source=state.pivotSourceLabel||"dashboard";panel.querySelectorAll(".empty-state").forEach(node=>node.remove());panel.hidden=false;$("pivotKind").textContent=kind.toUpperCase();$("pivotContext").textContent=`${source} → ${kind.replace("Selected: ","")} detail · Close detail returns to ${source}`;$("pivotRecommendationNav").hidden=!recommendationDetail;$("pivotTitle").textContent=title;$("pivotSummary").textContent=summary;$("defenderRemediationLink").hidden=!showRecommendationActions;$("copyRecommendationReference").hidden=!showRecommendationActions;$("recommendationTrackingActions").hidden=true;$("recommendationCurrentStatus").hidden=true;$("recommendationTrackingStatus").textContent="";$("pivotActionStatus").textContent="";if(showRecommendationActions&&recommendation){$("defenderRemediationLink").href=defenderRecommendationUrl(recommendation);}}
function renderPivotDetails(sections){$("pivotDetails").innerHTML=sections.map(section=>`<section class="pivot-subsection"><div class="panel-title"><h3>${esc(section.title)}</h3><span>${esc(section.subtitle||"")}</span></div><div class="table-wrap"><table id="${esc(section.id)}"></table></div></section>`).join("");}

function latestSecureScore(){
  const preferred=state.origin==="Synthetic"?state.secureScores.filter(row=>row.DataOrigin==="Synthetic"):state.secureScores.filter(row=>row.DataOrigin==="Live");
  return (preferred.length?preferred:state.secureScores).slice().sort((a,b)=>String(b.CreatedDateTime).localeCompare(String(a.CreatedDateTime)))[0];
}
function renderSecureScore(){
  const score=latestSecureScore(),percent=score?Number(score.ScorePercent||Number(score.CurrentScore||0)/Math.max(1,Number(score.MaxScore||0))*100):0,average=Number(score?.AllTenantsAverageScore||0),delta=percent-average;
  $("secureScoreCard").innerHTML=score?`<div class="secure-score-heading"><span>MICROSOFT SECURE SCORE</span><strong>${esc(score.DataOrigin||"Current")} evidence</strong></div><div class="secure-score-body"><div class="score-ring" style="--score:${Math.max(0,Math.min(100,percent))}"><strong>${percent.toFixed(1)}%</strong><span>attained</span></div><div class="secure-score-detail"><h3>${fmt(score.CurrentScore)} of ${fmt(score.MaxScore)} points</h3><p>${delta>=0?`${delta.toFixed(1)} points above`:`${Math.abs(delta).toFixed(1)} points below`} the reported tenant average of ${average.toFixed(1)}%.</p><small>Updated ${esc(formatUtc(score.CreatedDateTime||score.SnapshotTimeUtc))}</small></div></div>`:`<div class="secure-score-heading"><span>MICROSOFT SECURE SCORE</span></div><div class="secure-score-empty"><strong>Not available</strong><p>Secure Score was not present in this snapshot.</p></div>`;
}
function shiftUtcDate(date,days){const shifted=new Date(`${date}T00:00:00Z`);shifted.setUTCDate(shifted.getUTCDate()+days);return shifted.toISOString().slice(0,10);}
/** Print only the executive snapshot; browser print provides Save as PDF. */
function printExecutiveSnapshot(){document.body.classList.add("executive-snapshot-print");const cleanup=()=>document.body.classList.remove("executive-snapshot-print");window.addEventListener("afterprint",cleanup,{once:true});window.print();}

// Only bounded, snapshot-pinned query results enter the live dashboard.
const dashboardQuery={
  snapshot:null,expired:false,scopeKey:"",lastSearch:state.search,searchTimer:null,
  main:{sequence:0,controller:null},detail:{sequence:0,controller:null},
  tables:new Map(),detailTables:new Map(),lastResponse:null,reportReady:false,exportControllers:new Set(),exportSequence:0,
  responses:new Map(),responseBytes:0
};
const dashboardVisualProgress={timer:null,startedAt:null,checks:0};

function stopDashboardVisualProgress(){
  clearTimeout(dashboardVisualProgress.timer);
  dashboardVisualProgress.timer=null;
  dashboardVisualProgress.startedAt=null;
}

function updateDashboardProgressElapsed(){
  if(dashboardVisualProgress.startedAt===null)return;
  const seconds=Math.max(0,Math.floor((Date.now()-dashboardVisualProgress.startedAt)/1000));
  const elapsed=$("reportProgressElapsed");
  if(elapsed)elapsed.textContent=`Elapsed ${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,"0")}`;
}

function dashboardIndexPlanMarkup(progress,expanded=false){
  const plan=progress?.indexPlan||progress?.failure?.indexPlan;
  if(!Array.isArray(plan?.steps))return "";
  const completed=Number(plan.completedSteps)||0;
  return `<details class="index-progress-plan" data-index-plan${expanded?" open":""}><summary>${completed} of ${plan.steps.length} index preparation steps complete</summary><ol>${plan.steps.map((name,index)=>`<li>${esc(name)} — ${index<completed?"complete":index===completed?(progress.failure?"failed":"in progress"):"waiting"}</li>`).join("")}</ol></details>`;
}

function dashboardPhasePlanMarkup(progress,expanded=false){
  const plan=progress?.phasePlan;
  if(!Array.isArray(plan?.steps)||!Number.isInteger(plan.currentStep)||plan.currentStep<1||plan.currentStep>plan.steps.length)return "";
  const labels={
    "snapshot-indexes":"Restore or build snapshot indexes",
    "snapshot-aggregates":"Build dashboard reporting aggregates",
    "snapshot-search":"Restore supporting caches and prepare search",
    "snapshot-reports":"Prepare shared report views",
    "snapshot-publication":"Save reusable viewer caches",
    "query-workflow":"Read recommendation workflow state",
    "query-scope":"Select findings and date range",
    "query-results":"Build selected view",
    "query-recommendations":"Calculate recommendation impact and ranking",
    "query-summary":"Build summary metrics",
    "query-sla":"Calculate SLA metrics",
    "report-clocks":"Calculate finding lifecycle dates",
    "report-periods":"Summarize reporting periods",
    "report-risk":"Calculate severity and workload risk",
    "report-charts":"Build executive workload charts",
    "report-daily":"Build daily trend",
    "report-weekly":"Calculate weekly remediation",
    "report-history":"Build lifecycle history",
    "detail-workloads":"Load affected workloads",
    "detail-cves":"Load related CVEs",
    "detail-recommendations":"Load related recommendations",
    "detail-evidence":"Load finding evidence",
    "query-finalize":"Finalize report response",
  };
  const label=name=>labels[name]||name,current=plan.currentStep-1,remaining=plan.steps.length-plan.currentStep;
  return `<div class="report-phase-plan"><strong>Step ${plan.currentStep} of ${plan.steps.length}: ${esc(label(plan.steps[current]))}</strong><span>${remaining?`Next: ${esc(label(plan.steps[current+1]))} · ${remaining} phase${remaining===1?"":"s"} after this`:"Final phase"}</span><details class="index-progress-plan" data-phase-plan${expanded?" open":""}><summary>Preparation phases</summary><ol>${plan.steps.map((name,index)=>`<li${index===current?' aria-current="step"':""}>${esc(label(name))} — ${index<current?"earlier":index===current?(progress.failure?"failed":"in progress"):"remaining"}</li>`).join("")}</ol><small>Cached phases may be skipped. Phase counts do not estimate remaining time.</small></details></div>`;
}

function showDashboardVisualProgress(title,message,phase,progress=null){
  const expanded=$("loadingNotice").querySelector("[data-index-plan]")?.open;
  const phasesExpanded=$("loadingNotice").querySelector("[data-phase-plan]")?.open;
  const detailsExpanded=$("loadingNotice").querySelector("[data-progress-details]")?.open;
  $("loadingNotice").innerHTML=`<div class="loading-notice-content"><strong>${esc(title)}</strong><div class="report-progress-meta"><span id="reportProgressPhase">${esc(phase)}</span><span id="reportProgressElapsed" aria-live="off"></span></div><div class="report-progress-track" role="progressbar" aria-label="Report request in progress" aria-valuetext="${esc(phase)}"><span class="report-progress-indicator"></span></div><details class="scope-progress-details" data-progress-details${detailsExpanded?" open":""}><summary>Preparation details</summary>${message?`<span>${esc(message)}</span>`:""}${dashboardPhasePlanMarkup(progress,phasesExpanded)}${dashboardIndexPlanMarkup(progress,expanded)}</details></div>`;
  updateDashboardProgressElapsed();
}

function startDashboardVisualProgress(){
  stopDashboardVisualProgress();
  dashboardVisualProgress.startedAt=Date.now();
  dashboardVisualProgress.checks=0;
  showDashboardVisualProgress("Loading selected view","Querying the pinned snapshot for the current filters.","Waiting for server response");
  const tick=()=>{
    if($("loadingNotice").hidden){stopDashboardVisualProgress();return;}
    updateDashboardProgressElapsed();
    dashboardVisualProgress.timer=setTimeout(tick,1000);
  };
  dashboardVisualProgress.timer=setTimeout(tick,1000);
}

function hideDashboardLoadingNotice(){
  stopDashboardVisualProgress();
  $("loadingNotice").hidden=true;
}

function dashboardResponseKey(request){
  const filters={...request.filters};
  for(const key of ["activeView","snapshotTimeMs","selectedEntity","selectedRecommendationId","selectedCveDialogId","pivotSourceLabel"])delete filters[key];
  if(filters.newPeriod!=="custom"){delete filters.newPeriodStart;delete filters.newPeriodEnd;}
  if(filters.statisticsPeriod!=="custom"){delete filters.statisticsStartDate;delete filters.statisticsEndDate;}
  if(filters.executiveSnapshotPeriod!=="custom"){delete filters.executiveSnapshotStart;delete filters.executiveSnapshotEnd;}
  return JSON.stringify({...request,filters});
}

function clearDashboardResponseCache(){
  dashboardQuery.responses.clear();dashboardQuery.responseBytes=0;
}

function cacheDashboardResponse(key,payload){
  const bytes=JSON.stringify(payload).length*2;
  const previous=dashboardQuery.responses.get(key);
  if(previous){dashboardQuery.responseBytes-=previous.bytes;dashboardQuery.responses.delete(key);}
  if(bytes>2*1024*1024)return;
  dashboardQuery.responses.set(key,{payload,bytes,time:Date.now()});
  dashboardQuery.responseBytes+=bytes;
  while(dashboardQuery.responses.size>16||dashboardQuery.responseBytes>8*1024*1024){
    const oldest=dashboardQuery.responses.keys().next().value;
    dashboardQuery.responseBytes-=dashboardQuery.responses.get(oldest).bytes;
    dashboardQuery.responses.delete(oldest);
  }
}

function dashboardFilters(){
  const filters={};
  for(const [key,value] of Object.entries(state)){
    if(value instanceof Set)filters[key]=[...value];
    else if(value===null||["string","number","boolean"].includes(typeof value))filters[key]=value;
  }
  for(const id of ["statisticsStartDate","statisticsEndDate"])filters[id]=$(id)?.value||"";
  filters.workloadGrouping=workloadGroupingConfig;
  filters.recommendationTracking=[...state.recommendationTracking.values()];
  return filters;
}

function dashboardRequest(view=state.activeView,tableId=null,page=0){
  const request={snapshotId:dashboardQuery.snapshot?.snapshotId,view,filters:dashboardFilters(),mode:findingsList.mode,page,limit:FINDINGS_PAGE_SIZE};
  if(view==="slaDashboard"&&state.slaSummary.status){
    request.filters.slaSummaryStatus=state.slaSummary.status;
    request.filters.slaSummarySeverity=state.slaSummary.severity;
    request.filters.slaSummaryEntity=state.slaSummary.entity;
  }
  if(state.managementMetric?.view===view){
    request.filters.managementMetricEntity=state.managementMetric.entity;
    request.filters.managementMetricStatus=state.managementMetric.status;
  }
  if(view==="slaDashboard"&&state.slaCompliance.start&&state.slaCompliance.end){
    request.filters.slaComplianceStart=state.slaCompliance.start;
    request.filters.slaComplianceEnd=state.slaCompliance.end;
  }
  request.filters.managementReporting=true;
  request.filters.simplifiedDashboard=view==="recommendations";
  if(view==="trend"||(!PRIMARY_VIEWS[state.activeView]&&primaryView==="trend")){
    request.filters.newPeriod="reporting";
  }
  request.filters.includeFindingEvidence=false;
  if(tableId?.includes("Management"))request.limit=10;
  if(tableId)request.table=tableId;
  if(view==="detail"){
    request.selection=state.selectedEntity;request.filters.managementSourceView=state.pivotSourceLabel||state.activeView;
    if(state.selectedEntity?.type==="machine")request.filters.machineCveStatus=state.machineCveStatus;
    if(state.selectedEntity?.type==="machine"&&state.machineHistory.enabled){
      request.filters.machineHistoryPeriod=state.machineHistory.period;
      if(state.machineHistory.period==="custom"){
        request.filters.machineHistoryStart=state.machineHistory.start;
        request.filters.machineHistoryEnd=state.machineHistory.end;
      }
    }
  }
  return request;
}

function invalidateDashboardChannel(channel){
  channel.sequence++;
  channel.controller?.abort();
  channel.controller=null;
}

function dashboardStatus(message="",expired=false,retryable=true,informational=false){
  $("dashboardQueryStatus").hidden=!message;
  $("dashboardQueryStatus").setAttribute("role",informational?"status":"alert");
  $("dashboardQueryMessage").textContent=message;
  $("reloadDashboardSnapshot").hidden=!expired;
  $("retryDashboardQuery").hidden=!message||expired||!retryable;
}

function updateScopeLoading(view,busy){
  dashboardQuery[view==="detail"?"detail":"main"].busy=busy;
  const pending=Boolean(dashboardQuery.main.busy||dashboardQuery.detail.busy)&&!dashboardQuery.expired;
  $("scopeBusyIndicator").hidden=!pending;
  $("scopeProgress").setAttribute("aria-busy",String(pending));
  $("scopeProgress").classList.toggle("is-loading",pending);
}

function dashboardBusy(view,busy){
  const wasBusy=dashboardQuery.main.busy||dashboardQuery.detail.busy;
  updateScopeLoading(view,busy);
  const root=$(view==="detail"?"pivotPanel":view);
  root?.setAttribute("aria-busy",String(busy));
  root?.querySelectorAll("table,.metric-grid,.executive-kpi-grid,.decision-metrics,.donut-panel,.chart,.weekly-chart,.executive-trend-chart,.executive-severity-chart,.executive-concentration-chart,.executive-sla-meter-wrap,.secure-score-card,.recommendation-impact-grid,.executive-severity-status-grid,.server-pagination,.server-record,.sla-dashboard-visuals,.sla-leadership-snapshot,.sla-compliance-snapshots").forEach(node=>node.classList.toggle("query-pending",busy));
  if(busy){
    if(view!=="detail")$("filterCount").textContent="Loading matching scope…";
    $("loadingNotice").hidden=false;
    if(!wasBusy||view!=="detail")startDashboardVisualProgress();
  }else if(!dashboardQuery.main.busy&&!dashboardQuery.detail.busy)hideDashboardLoadingNotice();
}

function clearDashboardResults(view){
  if(view==="trend"){dashboardQuery.reportReady=false;$("printReporting").disabled=true;}
  const root=$(view);
  root?.querySelectorAll("table,.metric-grid,.executive-kpi-grid,.decision-metrics,.donut-panel,.chart,.weekly-chart,.executive-trend-chart,.executive-severity-chart,.executive-concentration-chart,.secure-score-card,.recommendation-impact-grid,.executive-severity-status-grid,.sla-dashboard-visuals,.sla-leadership-snapshot,.sla-compliance-snapshots").forEach(node=>node.innerHTML="");
  root?.querySelectorAll(".server-pagination").forEach(node=>node.remove());
  if(view==="overview")$("findingsPageStatus").textContent="Loading matching records…";
}

function expireDashboardSnapshot(){
  dashboardQuery.expired=true;
  clearDashboardResponseCache();
  clearTimeout(dashboardQuery.searchTimer);
  invalidateDashboardChannel(dashboardQuery.main);
  invalidateDashboardChannel(dashboardQuery.detail);
  for(const controller of dashboardQuery.exportControllers)controller.abort();
  dashboardBusy(state.activeView,true);
  if(state.selectedEntity)dashboardBusy("detail",true);
  hideDashboardLoadingNotice();
  updateScopeLoading(state.activeView,false);
  updateScopeLoading("detail",false);
  $("filterCount").textContent="New snapshot available — reload";
  dashboardStatus("New snapshot available. Reload to continue; results from different snapshots have not been combined.",true);
}

async function dashboardResponse(response,isCurrent=()=>true){
  if(response.status===409){expireDashboardSnapshot();throw new Error("Snapshot expired");}
  if(!response.ok){
    const payload=await response.json().catch(()=>({}));
    throw new Error(payload.detail||payload.error||`Dashboard request failed (${response.status}).`);
  }
  const payload=await response.json();
  if(!isCurrent())return null;
  if(payload.snapshotId!==dashboardQuery.snapshot?.snapshotId){
    expireDashboardSnapshot();throw new Error("Snapshot changed");
  }
  return payload;
}

function dashboardPreparationText(status){
  const progress=status.progress||{},stage=String(progress.failure?.stage||progress.stage||"waiting-for-data");
  const views={...PRIMARY_VIEWS,priority:"Recommendations",sla:"SLA",detail:"Selected item",help:"Help"};
  const phases={tracking:"recommendation workflow state",header:"activity and filter metadata","scope-counts":"finding counts","recommendation-matching":"recommendation matching","recommendation-impact":"recommendation impact totals","recommendation-ranking":"recommendation ranking","recommendation-details":"recommendation evidence","summary":"summary metrics and run comparison",sla:"SLA metrics","shared-clocks":"finding lifecycle dates (first seen, fixed, reopened and SLA due)","period-summaries":"current and previous reporting periods","daily-clocks":"daily finding and remediation trend","weekly-remediation":"weekly remediation totals","workload-and-charts":"workload breakdown and executive charts",report:"report calculations","detail-workloads":"affected workloads","detail-cves":"related CVEs","detail-recommendations":"related recommendations","detail-evidence":"finding evidence page"};
  let action=stage;
  if(stage.startsWith("load-rows:"))action=`Rebuilding ${stage.split(":")[1]} index`;
  else if(stage.startsWith("build-index:")){
    const [,dataset,position,name]=stage.split(":");
    action=`Building ${dataset} index ${position}: ${name}`;
  }
  else if(stage.startsWith("analyze-indexes:"))action=`Analyzing ${stage.split(":")[1]} query indexes`;
  else if(stage.startsWith("build-evidence:"))action=`Preparing ${stage.split(":")[1]} evidence: ${stage.split(":")[2]}`;
  else if(stage.startsWith("build-indexes:"))action=`Building ${stage.split(":")[1]} query indexes`;
  else if(stage.startsWith("download-query-index"))action="Downloading published data index";
  else if(stage==="restore-query-index")action="Restoring published data index";
  else if(stage==="validate-query-index")action="Validating published data index";
  else if(stage.startsWith("download:"))action=`Downloading ${stage.split(":")[1]} data`;
  else if(stage==="prepare-workspace-indexes")action="Preparing shared workspace indexes";
  else if(stage==="prepare-dashboard-read-model")action="Preparing shared dashboard aggregates";
  else if(stage==="prepare-search-index")action="Preparing searchable finding evidence";
  else if(stage.startsWith("search-index:"))action=`Preparing search index: ${stage.split(":").slice(1).join(" ").replace(/-/g," ")}`;
  else if(stage.startsWith("prepare-report:"))action=`Preparing shared ${views[stage.split(":")[1]]||stage.split(":")[1]} results`;
  else if(stage.startsWith("read-model:"))action=`Preparing shared dashboard aggregates: ${stage.split(":")[1].replace(/-/g," ")}`;
  else if(stage.startsWith("viewer-cache:")){
    const phase=stage.split(":")[1],operation=phase.split("-")[0],artifact=phase.slice(operation.length+1);
    const kind={primary:"query indexes","read-model":"dashboard aggregates","products-v1":"shared query results","search-v1":"search index","history-v10":"lifecycle evidence index"}[artifact]||artifact;
    action=`${{restore:"Restoring",validate:"Validating",publish:"Saving"}[operation]||operation} persistent ${kind}`;
  }
  else if(stage==="recommendation-tracking-read")action="Reading recommendation workflow state";
  else if(stage.startsWith("query:")){
    const [,view,phase]=stage.split(":");
    action=`Preparing ${views[view]||view}: ${phases[phase]||phase}`;
  }
  else if(stage.startsWith("view:"))action=`Preparing ${views[stage.split(":")[1]]||stage.split(":")[1]} view`;
  else if(stage==="querying-index")action="Querying data indexes";
  else if(stage==="waiting-for-query-worker")action="Waiting for an available query worker";
  if(stage==="query:slaDashboard:calendar-sla")action="Preparing SLA: calendar-period summaries";
  const stats=[];
  const phasePlan=progress.phasePlan;
  if(Array.isArray(phasePlan?.steps)&&Number.isInteger(phasePlan.currentStep)&&phasePlan.currentStep>0&&phasePlan.currentStep<=phasePlan.steps.length)stats.push(`Step ${phasePlan.currentStep} of ${phasePlan.steps.length}`);
  const plan=progress.indexPlan||progress.failure?.indexPlan;
  if(plan)stats.push(`${plan.completedSteps} / ${plan.totalSteps} index preparation steps complete`);
  if(Number.isFinite(progress.rows)){
    const dataset=stage.split(":")[1]?.replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase());
    const total=status.datasetRows?.[dataset];
    stats.push(Number.isFinite(total)?`${fmt(progress.rows)} / ${fmt(total)} rows processed`:`${fmt(progress.rows)} rows processed`);
  }
  if(Number.isFinite(progress.processedBytes))stats.push(`${(progress.processedBytes/1024/1024).toFixed(1)} MiB processed`);
  if(Number.isFinite(progress.elapsedSeconds))stats.push(`${Math.round(progress.elapsedSeconds)}s elapsed`);
  if(Number.isFinite(progress.stageSeconds))stats.push(`${Math.round(progress.stageSeconds)}s in current stage`);
  return [status.error,action,...stats].filter(Boolean).join(" · ");
}

let dashboardPreparationTimer=null;
let dashboardPreparationGeneration=0;
function pollDashboardPreparation(){
  clearTimeout(dashboardPreparationTimer);
  const generation=++dashboardPreparationGeneration;
  const poll=async()=>{
    try{
      const response=await apiFetch("/api/dashboard/status",{cache:"no-store"});
      if(!response.ok)throw new Error(`Preparation status unavailable (${response.status}).`);
      const status=await response.json();
      if(generation!==dashboardPreparationGeneration)return;
      const notice=$("dashboardPreparationStatus");
      notice.setAttribute("role",status.status==="error"?"alert":"status");
      const expanded=notice.querySelector("[data-index-plan]")?.open;
      const phasesExpanded=notice.querySelector("[data-phase-plan]")?.open;
      const newer=status.readySnapshotId&&status.readySnapshotId!==dashboardQuery.snapshot?.snapshotId;
      notice.hidden=status.status==="ready"&&!newer;
      notice.textContent=notice.hidden?"":status.status==="ready"
        ?"A newer complete snapshot is ready. Reload to select it; this page remains pinned to its original snapshot."
        :`${status.readySnapshotId?"Serving the previous complete snapshot. ":""}${dashboardPreparationText(status)}`;
      if(newer&&status.status==="ready"){
        notice.insertAdjacentHTML("beforeend",'<button id="loadLatestSnapshot" type="button">Load latest snapshot</button>');
        $("loadLatestSnapshot").addEventListener("click",()=>void startSnapshotDashboard());
      }
      if(!notice.hidden&&status.status!=="ready")notice.insertAdjacentHTML("beforeend",dashboardPhasePlanMarkup(status.progress,phasesExpanded)+dashboardIndexPlanMarkup(status.progress,expanded));
    }catch(error){
      if(generation!==dashboardPreparationGeneration)return;
      $("dashboardPreparationStatus").hidden=false;
      $("dashboardPreparationStatus").textContent=`Freshness check failed: ${error.message||"status unavailable"}. Displayed charts remain pinned to ${dashboardQuery.snapshot?.snapshotTimeUtc||"the loaded snapshot"}; retrying automatically.`;
    }finally{
      if(generation===dashboardPreparationGeneration)dashboardPreparationTimer=setTimeout(poll,15000);
    }
  };
  dashboardPreparationTimer=setTimeout(poll,15000);
}

async function startSnapshotDashboard(){
  clearTimeout(dashboardPreparationTimer);
  dashboardPreparationGeneration++;
  invalidateDashboardChannel(dashboardQuery.main);
  invalidateDashboardChannel(dashboardQuery.detail);
  dashboardQuery.expired=false;
  dashboardQuery.snapshot=null;
  dashboardQuery.scopeKey="";
  dashboardQuery.tables.clear();
  clearDashboardResponseCache();
  dashboardStatus();
  dashboardBusy(state.activeView,true);
  const channel=dashboardQuery.main,sequence=channel.sequence;
  channel.controller=new AbortController();
  try{
    let snapshot;
    for(;;){
      const response=await apiFetch("/api/dashboard/snapshot",{signal:channel.controller.signal,cache:"no-store"});
      if(sequence!==channel.sequence)return;
      if(!response.ok)throw new Error(`Snapshot unavailable (${response.status}).`);
      snapshot=await response.json();
      if(sequence!==channel.sequence)return;
      if(response.status!==202)break;
      if(snapshot.status!=="preparing")throw new Error("Invalid snapshot preparation status.");
      const status=snapshot.preparation||{};
      showDashboardVisualProgress(
        status.status==="error"?"Data preparation failed; retry scheduled":"Preparing dashboard data indexes",
        status.status==="error"?"":"May follow a server restart, first load, or new snapshot.",
        dashboardPreparationText(status),
        status.progress,
      );
      await waitForDashboardPoll(2000,channel.controller.signal);
    }
    if(!snapshot.snapshotId)throw new Error("Snapshot response is missing its identifier.");
    dashboardQuery.snapshot=snapshot;
    state.snapshotTimeMs=Date.parse(snapshot.snapshotTimeUtc);
    state.slaPolicy=snapshot.slaPolicy;
    $("freshnessText").textContent=formatLocal(snapshot.snapshotTimeUtc);
    $("freshnessLocalText").textContent=`UTC: ${formatUtc(snapshot.snapshotTimeUtc)}`;
    const date=String(snapshot.snapshotTimeUtc||"").slice(0,10);
    if(date){
      for(const [id,days] of [["statisticsStartDate",6],["statisticsEndDate",0],["executiveSnapshotStart",29],["executiveSnapshotEnd",0],["slaDashboardComplianceStart",89],["slaDashboardComplianceEnd",0]]){
        if(!$(id).value)$(id).value=shiftUtcDate(date,-days);
        $(id).max=date;
      }
    }
    render();
    pollDashboardPreparation();
    if(state.recommendationTrackingEnabled)void loadRecommendationTracking();
  }catch(error){
    if(sequence!==channel.sequence||error.name==="AbortError")return;
    hideDashboardLoadingNotice();
    updateScopeLoading(state.activeView,false);
    $("filterCount").textContent="Snapshot unavailable";
    $("freshnessText").textContent="Snapshot unavailable";
    dashboardStatus(error.message||"Dashboard snapshot could not be loaded.");
  }
}

/** Schedule just the selected view, never recomputing full-dataset metrics in the browser. */
function render(){
  if(dashboardQuery.expired){dashboardBusy(state.activeView,true);hideDashboardLoadingNotice();return;}
  if(!dashboardQuery.snapshot)return;
  const request=dashboardRequest(),scopeKey=JSON.stringify({...request,page:0});
  const searchChanged=state.search!==dashboardQuery.lastSearch;
  dashboardQuery.lastSearch=state.search;
  if(scopeKey!==dashboardQuery.scopeKey){
    dashboardQuery.scopeKey=scopeKey;
    dashboardQuery.tables.clear();
    state.recommendationsById.clear();
    findingsList.page=0;
    clearDashboardResults(state.activeView);
  }
  clearTimeout(dashboardQuery.searchTimer);
  invalidateDashboardChannel(dashboardQuery.main);
  dashboardBusy(state.activeView,true);
  $("filterCount").textContent="Loading matching scope…";
  for(const id of ["newCveCount","newMachineCount","newRecommendationCount","fixedWindowCveCount","fixedWindowMachineCount","fixedWindowRecommendationCount"])$(id).textContent="…";
  $("findingsMode").value=findingsList.mode;
  $("findingsSearch").value=$("searchFilter").value=state.search;
  $("pendingOnlyFilter").setAttribute("aria-pressed",String(state.exposureStatus==="PendingOnly"));
  $("pendingOnlyFilter").textContent=state.exposureStatus==="PendingOnly"?"Showing inactive":"Inactive only";
  $("applyNewPeriodFilter").checked=state.newPeriodFilter;
  $("toggleNewPeriodFilter").textContent=state.newPeriodFilter||state.remediationPeriodFilter?"Show all workspace data":"Limit workspace to newly observed vulnerabilities";
  $("newActivityBar").classList.toggle("filtering",state.newPeriodFilter||state.remediationPeriodFilter);
  renderScope();
  document.querySelectorAll(".latest-run-changes-toggle").forEach(input=>input.checked=state.latestRunChangesOnly);
  dashboardStatus();
  const refresh=()=>{void queryDashboardView();if(state.selectedEntity)void queryDashboardView("detail");};
  if(searchChanged)dashboardQuery.searchTimer=setTimeout(refresh,250);
  else refresh();
}

function dashboardQueryAbort(){
  const error=new Error("Dashboard query cancelled.");error.name="AbortError";return error;
}

function waitForDashboardPoll(milliseconds,signal){
  return new Promise((resolve,reject)=>{
    if(signal?.aborted){reject(dashboardQueryAbort());return;}
    const abort=()=>{clearTimeout(timer);signal?.removeEventListener("abort",abort);reject(dashboardQueryAbort());};
    const timer=setTimeout(()=>{signal?.removeEventListener("abort",abort);resolve();},milliseconds);
    signal?.addEventListener("abort",abort,{once:true});
  });
}

/** Poll one logical server query without changing its snapshot, filters or job ID. */
async function postDashboardQuery(request,{signal,isCurrent=()=>true,onPreparing=()=>{}}={}){
  const requestId=globalThis.crypto?.randomUUID?.()||`${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const body=JSON.stringify({...request,asyncQuery:true,requestId});
  const cancel=()=>{
    void fetch("/api/dashboard/query/cancel",{
      method:"POST",headers:{"Content-Type":"application/json"},keepalive:true,
      body:JSON.stringify({snapshotId:request.snapshotId,view:request.view,requestId}),
    }).then(response=>{if(!response.ok)throw new Error(`Cancellation request failed (${response.status}).`);})
      .catch(error=>console.warn("Could not release an abandoned dashboard query.",error));
  };
  if(signal?.aborted)throw dashboardQueryAbort();
  signal?.addEventListener("abort",cancel,{once:true});
  try{
    for(;;){
      if(signal?.aborted||!isCurrent())throw dashboardQueryAbort();
      const response=await apiFetch("/api/dashboard/query",{method:"POST",headers:{"Content-Type":"application/json"},body,signal});
      if(signal?.aborted||!isCurrent())throw dashboardQueryAbort();
      const payload=await dashboardResponse(response,isCurrent);
      if(signal?.aborted||!isCurrent())throw dashboardQueryAbort();
      if(response.status!==202)return payload;
      if(payload.status!=="preparing")throw new Error("The server returned an invalid query-preparation response.");
      const retryAfterSeconds=Number(payload.retryAfterSeconds);
      onPreparing(payload.progress,payload.preparation);
      await waitForDashboardPoll((Number.isFinite(retryAfterSeconds)&&retryAfterSeconds>0?retryAfterSeconds:2)*1000,signal);
    }
  }finally{
    signal?.removeEventListener("abort",cancel);
  }
}

async function queryDashboardView(view=state.activeView,tableId=null,page=0){
  if(!dashboardQuery.snapshot||dashboardQuery.expired)return;
  const detail=view==="detail",channel=detail?dashboardQuery.detail:dashboardQuery.main;
  invalidateDashboardChannel(channel);
  const sequence=channel.sequence,request=dashboardRequest(view,tableId,page);
  channel.controller=new AbortController();
  dashboardBusy(view,true);
  dashboardStatus();
  try{
    const key=dashboardResponseKey(request),cached=dashboardQuery.responses.get(key);
    const reusable=cached&&(!state.recommendationTrackingEnabled||Date.now()-cached.time<5000);
    const payload=reusable?cached.payload:await postDashboardQuery(request,{signal:channel.controller.signal,isCurrent:()=>sequence===channel.sequence&&!dashboardQuery.expired,onPreparing:(progress,preparation)=>{
      if(detail)$("pivotSummary").textContent=progress?dashboardPreparationText(preparation||{progress}):"Preparing exact snapshot detail; this panel will update automatically.";
      else{
        const checks=++dashboardVisualProgress.checks;
        showDashboardVisualProgress("Preparing exact snapshot results","The server has accepted this report for preparation; this view updates automatically when results are ready.",progress?dashboardPreparationText(preparation||{progress}):`Server preparation pending · ${checks} status check${checks===1?"":"s"}`,progress);
      }
    }});
    if(sequence!==channel.sequence||dashboardQuery.expired)return;
    renderDashboardResponse(payload,view,tableId);
    if(!reusable)cacheDashboardResponse(key,payload);
    else{dashboardQuery.responses.delete(key);dashboardQuery.responses.set(key,cached);}
    dashboardBusy(view,false);
    const notices=[...new Set([...(dashboardQuery.snapshot.notices||[]),...(payload.notices||[])])];
    dashboardStatus(notices.join(" · "),false,false);
  }catch(error){
    if(sequence!==channel.sequence||error.name==="AbortError"||dashboardQuery.expired)return;
    updateScopeLoading(view,false);
    const message=error.message||"Dashboard query failed. Retry to load this scope.";
    if(detail){
      dashboardBusy(view,false);
      if(!tableId)$("pivotTitle").textContent="Unable to load selected item";
      $("pivotSummary").textContent=`${message} Close this panel and select the item again to retry.`;
    }else{
      $("filterCount").textContent="Scope unavailable — retry";
      if(!dashboardQuery.detail.busy)hideDashboardLoadingNotice();
    }
    dashboardStatus(message);
  }
}

function dashboardRowAction(action,row){
  if(action==="machine")pivotToMachine(row);
  else if(action==="recommendation")pivotToRecommendation(row);
  else if(action==="cve")pivotToCve(row);
  else if(action==="finding")openDashboardDetail({type:"finding",id:String(row.FindingKey||row.FindingId||row.Id||row.id||`${row.RecommendationId||""}|${row.DeviceId||""}|${row.CveId||""}`)},row);
}

function renderDashboardTable(id,result,view){
  if(!$(id))return;
  if(!Array.isArray(result.items)||result.items.length>200)throw new Error("The server returned an oversized table page.");
  let target=id;
    if($(id).tagName&&$(id).tagName.toUpperCase()!=="TABLE"){
      target=`${id}Results`;$(id).innerHTML=`<div class="table-wrap"><table id="${esc(target)}"></table></div>`;
    }
    table(target,result.columns||[],result.items,result.action&&result.action!=="none"?row=>dashboardRowAction(result.action,row):false);
    $(target).querySelectorAll(".cve-link").forEach(button=>{
      button.addEventListener("click",event=>{event.stopPropagation();const row=result.items[Number(button.closest("tr").dataset.index)];if(row)pivotToCve(row);});
      button.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" ")event.stopPropagation();});
    });
  const tables=view==="detail"?dashboardQuery.detailTables:dashboardQuery.tables;
  tables.set(id,result);
  if(id==="executiveSnapshotStatus")return;
  if(result.action==="recommendation"){
    for(const row of result.items){const key=String(row.RecommendationId||row.id||"");state.recommendationsById.set(key,{...state.recommendationsById.get(key),...row});}
    if(view!=="detail")state.detailRecommendationIds=result.items.map(row=>String(row.RecommendationId||row.id||"")).filter(Boolean);
  }
  const total=Number(result.total||0),offset=Number(result.offset||0),limit=Math.min(200,Math.max(1,Number(result.limit||FINDINGS_PAGE_SIZE))),page=Math.floor(offset/limit),last=Math.max(0,Math.ceil(total/limit)-1);
  if(id==="findingsTable"){
    findingsList.page=page;
    $("findingsPageStatus").textContent=total?`${fmt(offset+1)}-${fmt(Math.min(offset+result.items.length,total))} of ${fmt(total)} ${result.rowLabel||(findingsList.mode==="cves"?"distinct CVEs":"finding instances")}`:`No matching ${findingsList.mode==="cves"?"CVEs":"finding instances"}`;
    document.querySelectorAll("[data-findings-page]").forEach(button=>button.disabled=!total||(["first","previous"].includes(button.dataset.findingsPage)?page===0:page>=last));
    return;
  }
  const pagerId=`${id}Pagination`;
  let pager=$(pagerId);
  if(!pager){pager=document.createElement("div");pager.id=pagerId;pager.className="server-pagination";const anchor=$(id).tagName?.toUpperCase()==="TABLE"?$(id).parentElement:$(id);anchor.insertAdjacentElement("afterend",pager);}
  pager.innerHTML=`<span role="status">${total?`${fmt(offset+1)}-${fmt(Math.min(offset+result.items.length,total))} of ${fmt(total)}${result.rowLabel?` ${esc(result.rowLabel)}`:""}`:"No matching records"}</span><div class="page-actions">${["First","Previous","Next","Last"].map((label,index)=>`<button type="button" data-query-page="${[0,Math.max(0,page-1),Math.min(last,page+1),last][index]}" ${!total||(index<2?page===0:page>=last)?"disabled":""}>${label}</button>`).join("")}<button type="button" data-query-export>Export CSV</button></div>`;
  pager.querySelectorAll("[data-query-page]").forEach(button=>button.addEventListener("click",()=>{void queryDashboardView(view,id,Number(button.dataset.queryPage));}));
  pager.querySelector("[data-query-export]").addEventListener("click",()=>{void exportDashboardCsv(view,id);});
}

function renderDashboardFacets(facets){
  if(!facets)return;
  const teams=facets.teams||[],subscriptions=facets.subscriptions||[],osTypes=facets.osTypes||[];
  $("osTypeFilter").innerHTML=`<option value="All">All operating systems</option>${osTypes.map(os=>`<option value="${esc(os)}">${esc(os)}</option>`).join("")}`;
  $("osTypeFilter").value=state.osType;
  state.subscriptionInventoryById.clear();
  subscriptions.forEach(row=>{const id=String(row.SubscriptionId||row.subscriptionId||row.id||"");if(id)state.subscriptionInventoryById.set(id,row);});
  const subscriptionOptions=subscriptions.map(row=>{const id=String(row.SubscriptionId||row.subscriptionId||row.id||"");return`<option value="${esc(id)}">${esc(row.SubscriptionName||row.DisplayName||row.displayName||row.name||id)}</option>`;}).join("");
  for(const id of ["subscriptionFilter","executiveSnapshotSubscription"]){
    $(id).innerHTML=`<option value="All">All subscriptions</option><option value="NoSubscription">No subscription</option>${subscriptionOptions}`;
    $(id).value=id==="subscriptionFilter"?state.subscription:state.executiveSnapshotSubscription;
  }
  for(const id of ["teamFilter","executiveSnapshotOwner"]){
    $(id).innerHTML=`<option value="All">All operating teams</option>${teams.map(team=>`<option value="${esc(team)}">${esc(team)}</option>`).join("")}`;
    $(id).value=id==="teamFilter"?state.team:state.executiveSnapshotOwner;
  }
}

function renderDashboardChart(id,chart){
  id=({executiveSnapshotSubscriptionConcentration:"executiveSubscriptionConcentration",executiveSnapshotOwnerConcentration:"executiveOwnerConcentration"})[id]||id;
  if(!$(id))return;
  if(chart.kind==="remediation-progress"){
    const series=[["withinSla","Open – within SLA","var(--blue)"],["pastSla","Open – past SLA","var(--red)"]];
    const scanSeries=[["detected","Detected on active devices","var(--blue)"],["inactive","On inactive devices","var(--muted)"]];
    const rows=chart.rows||[];
    const count=value=>Number.isSafeInteger(value)&&value>=0;
    for(const row of rows){
      if(!["open","resolved"].every(key=>count(row[key]))||!["new","baseline"].every(key=>row[key]===null||count(row[key]))||!series.every(([key])=>count(row.openBreakdown?.[key])))throw new Error("Vulnerability progress counts are incomplete. Retry the dashboard query.");
      if(series.reduce((sum,[key])=>sum+row.openBreakdown[key],0)!==row.open)throw new Error("Open CVE counts do not reconcile. Retry the dashboard query.");
      if(row.scanBreakdown&&(!scanSeries.every(([key])=>count(row.scanBreakdown[key]))||scanSeries.reduce((sum,[key])=>sum+row.scanBreakdown[key],0)!==row.open))throw new Error("Active and inactive CVE counts do not reconcile. Retry the dashboard query.");
    }
    const bars=(values,list,total)=>list.map(([key,label,color])=>`<div class="remediation-chart-row"><span>${label}</span><div class="remediation-chart-track" aria-hidden="true"><i style="width:${100*values[key]/Math.max(1,total)}%;background:${color}"></i></div><strong>${fmt(values[key])}</strong></div>`).join("");
    $(id).innerHTML=rows.length?`${rows.map(row=>`<section class="remediation-chart-period"><h4>${esc(row.label)}</h4><p class="coverage-note">${esc(row.start)} to ${esc(row.end)} UTC · ${esc(row.coverage)}</p>
      <p class="coverage-note">Inventory context for this date range: initial inventory (not new) <strong>${row.baseline===null?"Unavailable":fmt(row.baseline)}</strong> · first seen after baseline <strong>${row.new===null?"Unavailable":fmt(row.new)}</strong>.</p>
      <p><strong>${fmt(row.open)} open CVEs at period end</strong> · <strong>${fmt(row.resolved)}</strong> fixed during this period</p>
      ${bars(row.openBreakdown,series,row.open)}
      <p class="remediation-chart-equation">${fmt(row.open)} = ${series.map(([key])=>fmt(row.openBreakdown[key])).join(" + ")}.</p>
      ${row.scanBreakdown&&row.scanBreakdown.inactive?`<h5>Device activity</h5>${bars(row.scanBreakdown,scanSeries,row.open)}`:""}</section>`).join("")}
      <p class="coverage-note">${esc(fixRecognitionDescription())} ${chart.baselineTimeUtc?`Initial inventory was recorded ${esc(formatUtc(chart.baselineTimeUtc))}; it is not newly introduced risk.`:"Baseline history is unavailable; new versus initial-inventory counts cannot be assessed."}</p>
      <details class="remediation-chart-definitions"><summary>Counting and history definitions</summary><p>A CVE is fixed only when no machine in scope still has it open. A fix on one software item or one machine does not make the CVE fixed. Open CVEs are split by whether their earliest open machine/CVE deadline has passed. Inactive devices have not been seen for 7 days; their open CVEs are shown only when Include inactive devices is on. Initial inventory and later additions are historical context, not additional open categories. Partial history covers retained evidence only.</p></details>`
      :'<p class="coverage-note">No retained observations cover this reporting period; progress is unavailable, not zero.</p>';
    return;
  }
  if(chart.kind==="entity-severity"){
    if(chart.available===false){$(id).innerHTML='<p class="coverage-note">No retained observations cover this period; historical severity totals are unavailable, not zero.</p>';return;}
    $(id).innerHTML=[["machines","Machines / workload instances"],["cves","Unique CVEs"]].map(([key,title])=>`
      <article class="panel severity-summary" data-severity-entity="${key}">
        <div class="panel-title"><h3>${title} by severity${metricHelpButton("Severity")}</h3></div>
        <div class="severity-total-grid">${(chart.rows||[]).filter(row=>row.label!=="Unknown"||Number(row[key])>0).map(row=>`
          <button type="button" class="severity-total severity-${esc(String(row.label).toLowerCase())}" data-vulnerability-severity="${esc(row.label)}" aria-label="View ${esc(row.label)} vulnerabilities">
            <span>${esc(row.label)}</span><strong>${fmt(row[key])}</strong>
          </button>`).join("")}</div>
      </article>`).join("");
    bindSeverityVulnerabilityLinks(id);
    return;
  }
  if(chart.kind==="entity-sla-status"){
    if(chart.available===false){$(id).innerHTML='<p class="coverage-note">SLA status is unavailable before retained observations.</p>';return;}
    const columns=[["totalOpen","Open"],["openWithin","Open – within SLA"],["openOverdue","Open – past SLA"],["unknownOpen","Open – no SLA deadline"],["confirmedFixes","Fully cleared"],["completedWithin","Fixed – within SLA"],["completedLate","Fixed – past SLA"],["completedUnknown","Fixed – no SLA deadline"]];
    $(id).innerHTML=`<div class="table-wrap"><table class="sla-status-table"><caption>Distinct CVEs and machines, counted separately</caption>
      <thead><tr><th scope="col">Entity</th>${columns.map(([,label])=>`<th scope="col">${metricLabel(label)}</th>`).join("")}</tr></thead>
      <tbody>${(chart.rows||[]).map(row=>`<tr><th scope="row">${esc(row.label)}</th>${columns.map(([key])=>`<td>${fmt(row[key])}</td>`).join("")}</tr>`).join("")}</tbody>
    </table></div>`;
    return;
  }
  const rows=chart.rows||[],series=chart.series||[];
  let maximum=chart.unit==="percent"?100:1;
  for(const row of rows)for(const item of series)maximum=Math.max(maximum,Number(row[item.key]||0));
  if(chart.kind==="line"||chart.kind==="bars"){
    const width=960,height=260,pad=36,plotHeight=height-pad*2,plotWidth=width-pad*2,colors=["#1673c9","#21835b","#c83d4d","#d68a16"],x=index=>pad+(rows.length>1?index/(rows.length-1)*plotWidth:plotWidth/2),y=value=>height-pad-Math.max(0,Number(value||0))/maximum*plotHeight,label=row=>String(row.label||row.date||row.timestamp||""),every=Math.max(1,Math.ceil(rows.length/8));
    const chartSeries=series.map((item,seriesIndex)=>{
      const color=colors[seriesIndex%colors.length],points=rows.map((row,index)=>`${x(index)},${y(row[item.key])}`).join(" ");
      if(chart.kind==="line")return`<polyline fill="none" stroke="${color}" stroke-width="2.5" points="${points}"/>${rows.map((row,index)=>`<circle cx="${x(index)}" cy="${y(row[item.key])}" r="3" fill="${color}"><title>${esc(`${label(row)} · ${item.label||item.key}: ${fmt(row[item.key])}`)}</title></circle>`).join("")}`;
      const groupWidth=plotWidth/Math.max(1,rows.length),barWidth=Math.max(2,groupWidth/(series.length+1));
      return rows.map((row,index)=>`<rect fill="${color}" x="${pad+index*groupWidth+seriesIndex*barWidth}" y="${y(row[item.key])}" width="${barWidth}" height="${height-pad-y(row[item.key])}"><title>${esc(`${label(row)} · ${item.label||item.key}: ${fmt(row[item.key])}`)}</title></rect>`).join("");
    }).join("");
    $(id).innerHTML=rows.length?`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Snapshot-pinned management chart"><line x1="${pad}" y1="${height-pad}" x2="${width-pad}" y2="${height-pad}" stroke="#9bb0bf"/><text x="${pad}" y="18">${fmt(maximum)}${chart.unit==="percent"?"%":""}</text>${chartSeries}${rows.map((row,index)=>index%every===0||index===rows.length-1?`<text x="${chart.kind==="bars"?pad+(index+.5)*plotWidth/rows.length:x(index)}" y="${height-10}" text-anchor="middle">${esc(/^\d{4}-\d{2}-\d{2}/.test(label(row))?label(row).slice(5,10):label(row))}</text>`:"").join("")}</svg><div class="server-chart-legend">${series.map((item,index)=>`<span><i style="background:${colors[index%colors.length]}"></i>${metricLabel(item.label||item.key)}</span>`).join("")}</div>`:"No completed SLA outcomes with known deadlines in this scope.";
    return;
  }
  $(id).innerHTML=rows.map(row=>`<div class="server-chart-group"><strong>${esc(row.label||row.date||row.timestamp||row.Date||row.Severity||row.name||row.key||"")}</strong>${series.map(item=>`<div class="server-chart-row"><span>${metricLabel(item.label||item.key)}</span><i class="server-bar ${esc(item.className||"")}" style="width:${Math.max(0,Number(row[item.key]||0))/maximum*65}%"></i><strong>${esc(row[item.key]??"—")}</strong></div>`).join("")}${chart.kind==="concentration"?`<small>${fmt(row.criticalHigh)} Critical/High findings · ${fmt(row.machines)} machines</small>`:""}</div>`).join("")||"No matching chart data.";
}

function slaPolicyTarget(severity){
  const policies=(state.slaPolicy?.policies||[]).filter(policy=>policy.severity===severity);
  return policies.length?policies.map(policy=>`${policy.knownExploitRequired?"Known exploit":"Standard"}: ${fmt(policy.slaDays)} days`).join(" · "):"Waiting for policy data";
}

function bindSeverityVulnerabilityLinks(id){
  $(id).querySelectorAll("[data-vulnerability-severity]").forEach(button=>button.addEventListener("click",()=>openSeverityVulnerabilities(button.dataset.vulnerabilitySeverity)));
}

function openSeverityVulnerabilities(severity){
  const filters={severity};
  if(state.activeView==="executiveSnapshot"){
    filters.subscription=state.executiveSnapshotSubscription;
    filters.team=state.executiveSnapshotOwner;
  }
  findingsList.mode="cves";
  findingsList.page=0;
  activateView("overview",filters);
}

function slaDashboardPercent(value){
  return typeof value==="number"&&Number.isFinite(value)?`${value.toFixed(1)}%`:"Waiting for data";
}

function applyCompliancePeriod(view,clear=false){
  const start=clear?"":$(`${view}ComplianceStart`).value,end=clear?"":$(`${view}ComplianceEnd`).value;
  const snapshotDate=String(dashboardQuery.snapshot?.snapshotTimeUtc||"").slice(0,10);
  const validDate=value=>/^\d{4}-\d{2}-\d{2}$/.test(value)&&Number.isFinite(Date.parse(`${value}T00:00:00Z`))&&new Date(`${value}T00:00:00Z`).toISOString().slice(0,10)===value;
  if(!clear&&(!validDate(start)||!validDate(end)||start>end||!snapshotDate||end>snapshotDate)){
    $(`${view}ComplianceMessage`).textContent="Choose valid start and end dates, ordered and no later than the pinned snapshot.";
    return;
  }
  state.slaCompliance={start,end};
  for(const target of ["slaDashboard"]){
    $(`${target}ComplianceStart`).value=start;
    $(`${target}ComplianceEnd`).value=end;
    $(`${target}ComplianceMessage`).textContent="";
  }
  render();
}

function renderComplianceSnapshots(view,periods){
  const root=$(`${view}ComplianceCards`);
  if(!Array.isArray(periods)||!periods.length){
    root.innerHTML='<p class="coverage-note">Compliance percentages are unavailable. Refresh after the updated snapshot reports are ready.</p>';
    return;
  }
  const count=value=>typeof value==="number"&&Number.isFinite(value)&&value>=0;
  root.innerHTML=periods.map(period=>{
    const available=period.coverage==="complete";
    return `<article class="panel sla-compliance-period">
      <h3>${esc(period.label)}</h3><p class="coverage-note">${esc(period.start)} to ${esc(period.end)} UTC</p>
      ${available?"":'<p class="sla-compliance-history">Insufficient retained history for this entire period. Percentages are unavailable, not zero.</p>'}
      ${[["cves","Distinct CVEs"],["machines","Distinct machines"]].map(([key,title])=>{
        const values=period[key]||{};
        const rate=(label,help,percent,numerator,other,unknown,kind)=>{
          const known=available&&count(values[numerator])&&count(values[other]);
          const denominator=known?values[numerator]+values[other]:null;
          const noCompletions=known&&denominator===0&&percent==="completionPercent";
          return `<div class="sla-compliance-rate">
            <span>${metricLabel(label,help)}</span><strong>${noCompletions?"N/A - no fixes with known deadlines":slaDashboardPercent(known&&denominator>0?values[percent]:null)}</strong>
            <small>${known?`${fmt(values[numerator])} / ${fmt(denominator)} known-deadline ${kind}${denominator?"":"; none to assess"}`:"Numerator / denominator unavailable"}</small>
            ${percent==="openWithinPercent"?'<small>Still open. This is deadline status, not a completion rate.</small>':""}
            <small>${available&&count(values[unknown])?`${fmt(values[unknown])} deadline unknown (excluded)`:"Unknown-deadline count unavailable"}</small>
          </div>`;
        };
        return `<section class="sla-compliance-entity"><h4>${title}</h4>
          ${rate("Open – within SLA %","Open within SLA %","openWithinPercent","openWithin","openOverdue","unknownOpen","open")}
          ${rate("Fixed – within SLA %","Confirmed on-time %","completionPercent","completedWithin","completedLate","completedUnknown","fixed")}
        </section>`;
      }).join("")}
    </article>`;
  }).join("");
}

function slaCompletionAssessment(percent,confirmed,unit){
  if(!confirmed)return `No fully cleared ${unit} to assess`;
  if(typeof percent!=="number"||!Number.isFinite(percent))return "No known completion deadlines to assess";
  return `${slaDashboardPercent(percent)} of assessed fully cleared ${unit} were on time`;
}

function slaDashboardStack(values,labels,classes,label){
  const total=values.reduce((sum,value)=>sum+value,0);
  return `<div class="sla-severity-track" role="img" aria-label="${esc(`${label}: ${labels.map((name,index)=>`${fmt(values[index])} ${name}`).join(", ")}`)}">
    ${total?values.map((value,index)=>value?`<i class="${classes[index]}" style="width:${100*value/total}%"></i>`:"").join(""):""}
  </div><div class="sla-chart-legend">${labels.map((name,index)=>`<span><i class="${classes[index]}"></i>${fmt(values[index])} ${metricLabel(name)}</span>`).join("")}</div>`;
}

function unresolvedSeveritySnapshot(current){
  const cves=current.cves.severity,machines=current.machines.severity;
  const labels=["Critical","High","Medium","Low"];
  if([cves,machines].some(rows=>rows?.some(row=>row.label==="Unknown"&&row.totalOpen>0)))labels.push("Unknown");
  return `<section class="panel severity-summary" aria-label="Unresolved severity snapshot">
    <div class="panel-title"><h3>Unresolved exposure by severity${metricHelpButton("Severity")}</h3><span>CVEs and affected machines counted separately</span></div>
    <div class="severity-total-grid">${labels.map(label=>`
      <button type="button" class="severity-total severity-${esc(label.toLowerCase())}" data-vulnerability-severity="${esc(label)}" aria-label="View ${esc(label)} vulnerabilities">
        <span>${esc(label)}</span>
        ${[[cves,"Distinct unresolved CVEs"],[machines,"Affected machines"]].map(([rows,title])=>{
          const row=rows?.find(row=>row.label===label);
          const value=row?row.totalOpen:label==="Unknown"&&Array.isArray(rows)?0:undefined;
          return `<span class="severity-snapshot-count"><strong>${typeof value==="number"&&Number.isFinite(value)&&value>=0?fmt(value):"Waiting for data"}</strong><span>${title}</span></span>`;
        }).join("")}
      </button>`).join("")}</div>
    <p class="coverage-note">Each CVE and machine counts once, at its highest unresolved severity in the selected scope and snapshot or period end.
      Pending fixes remain unresolved. These are separate entity totals, not machine/CVE pairs or software records.</p>
  </section>`;
}

function slaLeadershipSnapshot(current,periodLabel){
  const chart=(title,values,labels,colors,unit,completion=false)=>{
    if(values.some(value=>typeof value!=="number"||!Number.isFinite(value)||value<0))throw new Error("SLA summary chart counts are unavailable.");
    const total=values.reduce((sum,value)=>sum+value,0);
    let position=0;
    const stops=values.map((value,index)=>{const start=position;position+=total?100*value/total:0;return `${colors[index]} ${start}% ${position}%`;});
    const description=labels.map((label,index)=>`${fmt(values[index])} ${label}`).join(", ");
    return `<article class="panel sla-snapshot-card${completion?" completed":""}">
      <h3>${metricLabel(title,completion?"Fully cleared":"Unresolved")}</h3>
      <p class="sla-snapshot-period">${completion?esc(periodLabel):"Current snapshot"}</p>
      <div class="sla-snapshot-body">
        <div class="sla-summary-donut" role="img" aria-label="${esc(`${title}: ${description}`)}" style="--sla-ring:${total?`conic-gradient(${stops.join(",")})`:"#dce4e9"}">
          <div><strong>${fmt(total)}</strong><span>${esc(unit)}</span></div>
        </div>
        <ul class="sla-snapshot-legend">${labels.map((label,index)=>`<li><i style="background:${colors[index]}"></i><span>${metricLabel(label)}</span><strong>${fmt(values[index])}</strong></li>`).join("")}</ul>
      </div>
      <p class="sla-snapshot-note">${completion?total?slaCompletionAssessment(current[unit==="CVEs"?"cves":"machines"].completionPercent,total,unit):"No full fixes in this period; no completion percentage to assess.":total?"A CVE or machine stays open until every machine/CVE pair is fixed.":"Nothing open in this scope."}</p>
    </article>`;
  };
  return `<section class="sla-leadership-snapshot" aria-label="Leadership SLA snapshot">
    <div class="section-heading"><div><h2>SLA at a glance${metricHelpButton("Current SLA status")}</h2></div><p>Remaining exposure now and confirmed full clearance during the reporting period. CVEs and machines are separate totals, never added together.</p></div>
    <div class="sla-snapshot-grid">${[["cves","CVEs"],["machines","machines"]].map(([entity,unit])=>{
      const values=current[entity];
      return chart(`${unit==="CVEs"?"CVEs":"Machines"} remaining`,[values.openWithin,values.openOverdue,values.unknownOpen],["Open – within SLA","Open – past SLA","Open – no SLA deadline"],["#557e9d","#c56822","#8694a0"],unit);
    }).join("")}
    ${[["cves","CVEs"],["machines","machines"]].map(([entity,unit])=>{
      const values=current[entity];
      return chart(`${unit==="CVEs"?"CVEs":"Machines"} fully cleared`,[values.completedWithin,values.completedLate,values.completedUnknown],["Fixed – within SLA","Fixed – past SLA","Fixed – no SLA deadline"],["#21835b","#bb3e4c","#8694a0"],unit,true);
    }).join("")}</div>
    <p class="coverage-note">${esc(fixRecognitionDescription())} Fully cleared means nothing is left open in scope, not a count of patches installed. Inactive devices never count as fixed. Unknown deadlines are excluded from the on-time percentage. Open now and fixed during the period are different measures, not slices of one total.</p>
  </section>`;
}

function slaCalendarComparison(title,current,previous){
  const range=period=>`${period.start} - ${period.end}`;
  const metric=(entity,unit,key,label,completions=false)=>{
    const known=period=>period.coverage==="complete";
    const change=known(current)&&known(previous)?current[entity][key]-previous[entity][key]:null;
    return `<section class="sla-calendar-metric"><h4>${metricLabel(label,completions?"Fully cleared":"Unresolved")}</h4>
      ${[previous,current].map(period=>`<div class="sla-calendar-row" data-coverage="${esc(period.coverage)}">
        <div><span>${esc(period.label)}</span><small>${esc(range(period))}</small><strong>${known(period)?`${fmt(period[entity][key])} ${unit} ${completions?"fully cleared":"unresolved"}`:"Waiting for data"}</strong></div>
        ${known(period)?completions?`<p>${fmt(period[entity].completedWithin)} on time · ${fmt(period[entity].completedLate)} late · ${fmt(period[entity].completedUnknown)} deadline unknown</p><p>${esc(slaCompletionAssessment(period[entity].completionPercent,period[entity].confirmedFixes,unit))}</p>`:
          slaDashboardStack([period[entity].openWithin,period[entity].openOverdue,period[entity].unknownOpen],["not yet due","overdue","deadline unknown"],["sla-status-within","sla-status-overdue","sla-status-unknown"],`${period.label} unresolved ${unit}`):
          '<small class="sla-history-gap">Full-period history is unavailable.</small>'}
      </div>`).join("")}
      <p class="sla-period-change">${change==null?"Change: Waiting for data":`Change: ${change>0?"+":""}${fmt(change)} ${unit} ${completions?"fully cleared":"unresolved"}`}</p>
    </section>`;
  };
  return `<article class="panel sla-calendar-panel"><div class="panel-title"><h3>${metricLabel(title)}</h3><span>Completed calendar periods · UTC</span></div>
    ${[["cves","CVEs"],["machines","machines"]].map(([entity,unit])=>
      metric(entity,unit,"totalOpen",`Distinct ${unit} unresolved at period end`)+
      metric(entity,unit,"confirmedFixes",`Distinct ${unit} fully cleared during period`,true)).join("")}
  </article>`;
}

function renderSimpleSla(summary){
  const root=$("slaDashboardSummary");
  $("slaSummaryDetails").hidden=!state.slaSummary.status;
  if(summary?.unit!=="machine-cve"||!Array.isArray(summary.severity)){
    root.innerHTML='<p role="status">Machine/CVE SLA summary unavailable. Update the Web App and reload this snapshot.</p>';
    return;
  }
  const statusLabels={Open:"Open",Fixed:"Fixed",OpenWithin:"Open – within SLA",OpenOverdue:"Open – past SLA",FixedWithin:"Fixed – within SLA",FixedLate:"Fixed – past SLA",Unknown:"No SLA deadline"};
  const link=(severity,status,value)=>`<button type="button" class="cve-link" data-sla-summary-severity="${esc(severity)}" data-sla-summary-status="${status}" aria-label="View ${esc(severity)} ${esc(statusLabels[status])} machine/CVE pairs">${value}</button>`;
  const rows=summary.severity.map(row=>{
    for(const key of ["openWithin","openOverdue","unknownOpen","completedWithin","completedLate","completedUnknown"]){
      if(typeof row[key]!=="number"||!Number.isFinite(row[key])||row[key]<0)throw new Error("Machine/CVE SLA summary counts are incomplete. Retry the dashboard query.");
    }
    const open=row.openWithin+row.openOverdue+row.unknownOpen,fixed=row.completedWithin+row.completedLate+row.completedUnknown;
    const known=row.completedWithin+row.completedLate;
    return `<tr><th scope="row">${esc(row.label)}</th><td>${link(row.label,"Open",fmt(open))}</td><td>${link(row.label,"Fixed",fmt(fixed))}</td>
      <td>${link(row.label,"OpenWithin",fmt(row.openWithin))}</td><td>${link(row.label,"OpenOverdue",fmt(row.openOverdue))}</td>
      <td>${link(row.label,"FixedWithin",fmt(row.completedWithin))}</td><td>${link(row.label,"FixedLate",fmt(row.completedLate))}</td>
      <td>${known?slaDashboardPercent(100*row.completedWithin/known):"N/A"}</td>
      <td>${link(row.label,"Unknown",fmt(row.unknownOpen+row.completedUnknown))}</td></tr>`;
  }).join("");
  root.innerHTML=`<article class="panel sla-simple-summary" aria-label="Simple machine/CVE SLA summary">
    <div class="panel-title"><h2>SLA by severity — open and fixed</h2><span>Machine/CVE pairs</span></div>
    <p>Open at the current snapshot; fixes during ${esc(summary.label)} (${esc(summary.start)} to ${esc(summary.end)} UTC).</p>
    <div class="table-wrap"><table><thead><tr><th scope="col">Severity</th><th scope="col">Open</th><th scope="col">Fixed</th><th scope="col">Open – within SLA</th><th scope="col">Open – past SLA</th><th scope="col">Fixed – within SLA</th><th scope="col">Fixed – past SLA</th><th scope="col">Fixed on time %</th><th scope="col">No SLA deadline</th></tr></thead><tbody>${rows}</tbody></table></div>
    <p class="coverage-note">${esc(fixRecognitionDescription())} One CVE on three machines counts as three machine/CVE pairs; software versions do not multiply counts. A pair is fixed only when none of its software is still detected.
      Fixed on time % = Fixed – within SLA ÷ (Fixed – within SLA + Fixed – past SLA). Pairs without a known deadline are excluded. Click any count for its evidence.</p>
    ${summary.coverage==="complete"?"":'<p class="coverage-note">Incomplete retained history: current open status is available, but fixes cover retained observations only, not necessarily the entire month.</p>'}
  </article>`;
  root.querySelectorAll("[data-sla-summary-status]").forEach(button=>button.addEventListener("click",()=>{
    state.slaSummary={severity:button.dataset.slaSummarySeverity,status:button.dataset.slaSummaryStatus};
    render();
  }));
  $("slaSummaryContext").textContent=state.slaSummary.status
    ?`${state.slaSummary.severity} · ${statusLabels[state.slaSummary.status]} · ${summary.start} to ${summary.end} UTC. One row per machine/CVE pair; workspace scope and pinned snapshot preserved.`
    :"";
}

function renderSlaDashboard(report){
  if(report?.unit!=="distinct-entities"||report.periods?.length!==5||!report.machineCveSummary||!Array.isArray(report.pairPeriods))throw new Error("The SLA dashboard response is incomplete. Retry after the Web App update is complete.");
  const summary=report.machineCveSummary,[,week,previousWeek,month,previousMonth]=report.pairPeriods,range=`${summary.start} to ${summary.end} UTC`;
  $("slaDashboardContext").textContent=`Snapshot: ${formatUtc(report.asOfUtc)}. Open status is current; fixes cover ${summary.label} (${range}). Each count is a machine/CVE pair.`;
  $("slaDashboardOverview").innerHTML=`
    <div class="sla-policy-chips">${["Critical","High","Medium","Low"].map(severity=>`<span><b>${severity}</b>${esc(slaPolicyTarget(severity))}</span>`).join("")}</div>
    ${fourStateTiles(summary.severity,`Machine/CVE pairs. Open now; fixed during ${summary.label}.`)}
    <article class="panel sla-gauge-panel">
      <div class="panel-title"><h3>SLA by severity${metricHelpButton("SLA gauge")}</h3><span>Machine/CVE pairs</span></div>
      <div class="sla-gauge-grid">${slaGaugeGrid(summary.severity,summary.label)}</div>
    </article>
    <article class="panel">
      <div class="panel-title"><h3>Open vs fixed over time${metricHelpButton("Open vs fixed over time")}</h3><span>Machine/CVE pairs, last 90 days</span></div>
      <div id="slaDashboardOpenFixed"></div>
    </article>`;
  $("slaDashboardSummary").hidden=false;
  renderSimpleSla(summary);
  $("slaSummaryDetails").hidden=!state.slaSummary.status;
  $("slaDashboardVisuals").innerHTML=`
    <div class="sla-calendar-grid">
      ${fourStateComparison("Week over week",previousWeek,week)}
      ${fourStateComparison("Month over month",previousMonth,month)}
    </div>
    <details class="panel sla-definitions"><summary>How SLA states are counted</summary>
      <p>${esc(fixRecognitionDescription())} Incomplete collections and inactive devices never count as fixes. A vulnerability that comes back starts a new episode with a new SLA clock.</p>
      <p>A machine/CVE pair's deadline is its earliest software record's first-seen date plus the policy days for its severity. A pair is fixed only when none of its software is still detected, at the time the last software item was removed.</p>
      <p>${summary.coverage==="complete"?"The month-to-date period is covered.":"Partial retained coverage: fixes cover retained observations only, not necessarily the entire month."} ${report.history?.startUtc?`History begins ${esc(formatUtc(report.history.startUtc))}.`:"History coverage is unavailable."}</p>
    </details>`;
  $("slaSummaryContext").textContent=state.slaSummary.status?`${state.slaSummary.severity==="All"?"All severities":state.slaSummary.severity} · ${state.slaSummary.status} · workspace filters and pinned snapshot preserved.`:"";
}

function renderDashboardResponse(payload,view,tableId){
  const activityMode=state.newPeriodFilter||state.remediationPeriodFilter||state.latestRunChangesOnly;
  if(view==="workstations"){
    $("assetInventoryControls").hidden=activityMode;
    $("endpointInventoryHelp").hidden=activityMode;
    $("workstationsTitle").textContent=activityMode?"Machines with matching activity":"Endpoint device inventory";
    $("workstationsContext").textContent=activityMode
      ?"Distinct machine IDs supported by the selected activity evidence, including historical or cloud machines without a current endpoint inventory record. Your workspace scope and activity window are retained."
      :"Defender endpoint inventory only. Cloud resources without endpoint device records are not counted here. Activity shortcuts instead list matching machine IDs from retained finding evidence.";
    $("workstationListTitle").textContent=activityMode?"Machines behind the activity count":"Endpoint devices and grouped scale-out workloads";
    $("workstationListContext").textContent=activityMode?"One row per machine ID, not a collapsed workload group. Open a machine for CVEs, recommendations, and dated evidence.":"Endpoint inventory, operating system, and coverage status; machine details contain CVEs and recommendations";
  }
  if(view==="recommendations"){
    $("recommendationCatalogControls").hidden=activityMode;
    $("recommendationCatalogContext").textContent=activityMode
      ?"Recommendations linked to the selected activity evidence. One row per recommendation ID, including retained evidence without a current catalog entry. Open a recommendation for its dated observations."
      :"Unresolved actions first, ranked by criticality, known exploit, overdue CVEs, affected machines, and distinct CVEs. Work status is coordination, not proof of a fix.";
  }
  if(view==="slaDashboard")renderSlaDashboard(payload.metadata?.slaDashboard);
  if(view==="jobHistory"){
    $("jobHistoryRecognition").textContent=fixRecognitionDescription()+" Windows Update status does not establish that third-party software is patched. A machine is fully cleared only when no unresolved CVE remains.";
  }
  if(view==="slaDashboard")renderComplianceSnapshots(view,payload.metadata?.slaDashboard?.compliancePeriods);
  ensureManagementReport(view);
  renderManagementSla(view,payload.metadata?.management?.sla,payload.metadata?.management?.periods,payload.charts);
  if(view==="trend")$("lifecycleOsBreakdown").hidden=state.reportingBreakdown==="All";
  const selectedRecommendation=state.recommendationsById.get(state.selectedRecommendationId);
  state.recommendationsById.clear();
  if(selectedRecommendation)state.recommendationsById.set(state.selectedRecommendationId,selectedRecommendation);
  if(view==="detail"){if(!tableId)prepareDashboardDetail(payload);}
  else{
    dashboardQuery.lastResponse=payload;
    renderDashboardFacets(payload.facets);
    if(payload.metadata){
      state.runs=payload.metadata.runs||[];state.runHistory=payload.metadata.runHistory||[];state.secureScores=payload.metadata.secureScores||[];
      renderRecentRuns();
      renderSecureScore();
    }
    const scope=payload.scope||{};
    const management=payload.metadata?.management?.periods?.[0];
    const slaCurrent=payload.metadata?.slaDashboard?.periods?.[0];
    $("filterCount").textContent=view==="workstations"&&activityMode
      ?`${fmt(scope.activityMachines)} machines with matching activity`
      :slaCurrent
      ?`${fmt(slaCurrent.cves.totalOpen)} distinct unresolved CVEs · ${fmt(slaCurrent.machines.totalOpen)} affected machines`
      :management
      ?`${fmt(management.machines.Open)} machines with open risk · ${fmt(management.cves.Open)} unique open CVEs · ${fmt(management.recommendations.Open)} open recommendations`
      :`${fmt(scope.detectedCves)} detected CVEs · ${fmt(scope.pendingCves)} CVEs with some pending evidence (can overlap detected) · ${fmt(scope.recommendations)} recommendations`;
    // Scope text/chips use only the serialized filters, not the unloaded findings.
    renderScope();
    const activityIds={newCves:"newCveCount",newMachines:"newMachineCount",newRecommendations:"newRecommendationCount",fixedCves:"fixedWindowCveCount",fixedMachines:"fixedWindowMachineCount",fixedRecommendations:"fixedWindowRecommendationCount"};
    const comparisonUnavailable=state.newPeriod==="runs"&&!payload.metadata?.activityComparison?.available;
    for(const [key,id] of Object.entries(activityIds))$(id).textContent=comparisonUnavailable?"N/A":fmt(payload.activity?.[key]);
    const reportingWindow=payload.metadata?.activityWindow;
    const range=reportingWindow?{start:Date.parse(reportingWindow.startUtc),end:Date.parse(reportingWindow.endUtc),label:"Observed activity in the selected reporting period",exclusiveStart:reportingWindow.exclusiveStart}:newPeriodRange();
    $("newActivityTitle").textContent=range?`${state.newPeriodFilter?"Filtering newly observed vulnerabilities · ":state.remediationPeriodFilter?"Filtering remediation observations · ":""}${range.label}`:comparisonUnavailable?"Run comparison unavailable":"Choose a valid custom range";
    $("newActivityContext").textContent=range?`${range.exclusiveStart?"After ":""}${formatUtc(range.start)} through ${formatUtc(range.end)} · counts use first-seen or remediation-observed timestamps inside this UTC window`:comparisonUnavailable?"Two comparable successful or partial runs are required. No daily-window fallback is being shown.":"The custom start date must not be after the end date.";
    $("availabilityItems").innerHTML=`<span class="header-status-item available"><i aria-hidden="true"></i><strong>Pinned snapshot</strong><span>${esc(dashboardQuery.snapshot.runId||dashboardQuery.snapshot.snapshotId)}</span></span>`;
  }
  for(const [id,items] of Object.entries(payload.cards||{}))if($(id))cards(id,items,"",payload.metadata?.metricActions?.[id]);
  for(const [id,text] of Object.entries(payload.texts||{}))if($(id)&&!["freshnessText","freshnessLocalText","filterCount"].includes(id))$(id).textContent=text;
  for(const [id,result] of Object.entries(payload.tables||{}))if(!tableId||id===tableId)renderDashboardTable(id,result,view);
  if(view==="executiveSnapshot"){
    $("executiveSnapshotGenerated").textContent=`Pinned snapshot: ${formatUtc(dashboardQuery.snapshot.snapshotTimeUtc)}`;
  }
  for(const [id,chart] of Object.entries(payload.charts||{}))renderDashboardChart(id,chart);
  if(view==="trend"){
    $("reportingScope").textContent=`Scope: ${$("scopeSummary").textContent} · ${state.origin} origin · OS: ${state.osType} · Domains: ${[...state.domains].join(", ")} · Recommendation types: ${[...state.recommendationTypes].join(", ")}`;
    dashboardQuery.reportReady=Boolean(payload.tables?.trendManagementComparisonTable);
    $("printReporting").disabled=!dashboardQuery.reportReady;
  }
  const detailPanel=$(view+"ManagementDetail");
  if(detailPanel){
    const selected=state.managementMetric?.view===view?state.managementMetric.table:null;
    detailPanel.hidden=!selected;
    detailPanel.querySelectorAll("[data-management-table]").forEach(section=>section.hidden=section.dataset.managementTable!==selected);
  }
  if(!tableId&&state.managementMetric?.view===view)$(state.managementMetric.table)?.scrollIntoView({behavior:"smooth",block:"center"});
  if(state.managementMetric?.view===view){
    const details=$(state.managementMetric.table)?.closest("details");
    if(details)details.open=true;
  }
  if(!tableId&&view==="slaDashboard"&&state.slaSummary.status)$("slaSummaryDetails").scrollIntoView({behavior:"smooth",block:"center"});
}

function ensureManagementReport(view){
  const root=$(view+"Management");
  if(root)  root.hidden=view==="overview";
  if(!root||root.dataset.initialized)return;
  root.dataset.initialized="true";
  const prefix=view+"Management";
  const openFixedPanel=label=>`<article class="panel">
        <div class="panel-title"><h3>Open vs fixed over time${metricHelpButton("Open vs fixed over time")}</h3><span>Machine/CVE pairs, ${label}</span></div>
        <div id="${prefix}OpenFixed"></div>
      </article>`;
  if(view==="executiveSnapshot"){
    root.innerHTML=`
    <section class="management-report" aria-label="Executive SLA report">
      <p id="${prefix}Context" class="coverage-note"></p>
      <div id="${prefix}Cards" class="metric-grid"></div>
      <div id="${prefix}Tiles"></div>
      <article class="panel sla-gauge-panel">
        <div class="panel-title"><h3>SLA by severity${metricHelpButton("SLA gauge")}</h3><span>Machine/CVE pairs</span></div>
        <div id="${prefix}SlaGauges" class="sla-gauge-grid"></div>
      </article>
      ${openFixedPanel("selected period")}
      <div id="${prefix}Comparison"></div>
      <div id="${prefix}Severity" class="management-severity"></div>
      <article class="panel"><div class="panel-title"><h3>Machines${metricHelpButton("Status and progress")}</h3><span>Past-SLA machines first. Export for the full list.</span></div><div class="table-wrap"><table id="${prefix}MachineTable"></table></div></article>
      <article class="panel"><div class="panel-title"><h3>Vulnerabilities (unique CVEs)</h3><span>Past-SLA CVEs first. Export for the full list.</span></div><div class="table-wrap"><table id="${prefix}CveTable"></table></div></article>
      <details class="management-detail"><summary>Recommendations: status${metricHelpButton("Status and progress")}</summary>
        <div class="table-wrap"><table id="${prefix}RecommendationTable"></table></div>
      </details>
      <p id="${prefix}PolicyRules" class="coverage-note"></p>
      <p class="coverage-note">A CVE is fixed only when no in-scope machine still has it open; a machine is fixed only when no in-scope CVE is still open.
        ${esc(fixRecognitionDescription())}
        Inactive devices (not seen for 7 days) never count as fixed; their open CVEs are shown only when Include inactive devices is on.</p>
    </section>`;
    return;
  }
  if(view==="trend"){
    root.innerHTML=`
    <section class="management-report" aria-label="Reporting period summary">
      <p id="${prefix}Context" class="coverage-note"></p>
      <div id="${prefix}PeriodTotals"></div>
      ${openFixedPanel("selected period")}
      <div id="${prefix}Comparison"></div>
      <p id="${prefix}PolicyRules" class="coverage-note"></p>
      <p class="coverage-note">${esc(fixRecognitionDescription())} A vulnerability that comes back starts a new episode with a new SLA clock.
        Inactive devices (not seen for 7 days) never count as fixed; their open CVEs are shown only when Include inactive devices is on.</p>
    </section>`;
    return;
  }
  const slaSnapshot=`
    <article class="panel management-sla-snapshot" aria-label="Quick SLA status by entity">
      <div class="panel-title"><h3>${metricLabel("Current SLA status")}</h3><span>Distinct CVEs and machines, counted separately</span></div>
      <div id="${prefix}SlaSnapshot"></div>
      <p id="${prefix}PolicyRules" class="coverage-note"></p>
      <p class="coverage-note">Each CVE and machine counts once in its own total. Software and version evidence does not multiply either count.
        Open status is assessed at the pinned snapshot; full clearances are in the stated reporting period.
        A CVE or machine stays open until every machine/CVE pair is fixed. Known overdue or late status takes precedence over missing deadlines.
        The SLA screen provides severity and calendar comparisons in these same units.</p>
    </article>`;
  root.innerHTML=`
    <section class="management-report" aria-label="Machine and vulnerability management summary">
      <div class="section-heading"><div><span>MACHINES AND VULNERABILITIES</span><h2>${view==="executive"?"Current machines and vulnerabilities":"Open risk and fixes"}${metricHelpButton(view==="executive"?"Summary":"Status and progress")}</h2></div></div>
      <p id="${prefix}Context" class="coverage-note"></p>
      <div id="${prefix}Cards" class="metric-grid"></div>
      <div id="${prefix}FixActivity" class="metric-grid"></div>
      ${view==="executive"?`<article class="panel sla-gauge-panel">
        <div class="panel-title"><h3>SLA by severity${metricHelpButton("SLA gauge")}</h3><span>Machine/CVE pairs</span></div>
        <div id="${prefix}SlaGauges" class="sla-gauge-grid"></div>
      </article>
      <article class="panel">
        <div class="panel-title"><h3>Open vs fixed over time${metricHelpButton("Open vs fixed over time")}</h3><span>Machine/CVE pairs, last 90 days</span></div>
        <div id="${prefix}OpenFixed"></div>
      </article>`:""}
      <article class="panel">
        <div class="panel-title"><h3>Vulnerability inventory and remediation</h3><span>Distinct CVEs in the reporting periods</span></div>
        <div id="${prefix}RemediationProgress"></div>
      </article>
      <div id="${prefix}LeadershipSnapshot"></div>
      <p class="coverage-note">A CVE is fixed only when no in-scope machine still has it open; a machine is fixed only when no in-scope CVE is still open.
        ${esc(fixRecognitionDescription())}
        Inactive devices (not seen for 7 days) never count as fixed; their open CVEs are shown only when Include inactive devices is on.
        This measures observed fixes, not the exact patch-installation time.</p>
      <div id="${prefix}Severity" class="management-severity"></div>
      <p class="coverage-note">Each machine/workload instance is counted once, at its highest remaining CVE severity in this scope.
        Workload groups are not collapsed into a single machine. Each unique CVE is counted once at its highest remaining severity across the selected machines.
        Unknown severity is shown separately when present.
        A CVE on 500 machines is one vulnerability, not 500 vulnerabilities.</p>
      ${view==="executive"?slaSnapshot:`
      <section class="management-sla" aria-label="Machine and CVE SLA tracking">
        ${slaSnapshot}
        <div class="subsection-heading"><div><span>MACHINE / CVE SLA</span><h3>Fixes against policy deadlines</h3></div></div>
        <div id="${prefix}SlaStatus" class="management-sla-status" role="status"></div>
        <p id="${prefix}SlaPolicy" class="coverage-note"></p>
        <p class="coverage-note">Each CVE and machine is assessed once, after all its in-scope machine/CVE pairs are fixed.
          It is Fixed – past SLA if any pair was fixed late; missing deadlines stay unknown unless lateness is already known.
          Open items are never counted as fixed on time.</p>
        <div class="executive-snapshot-grid">
          <article class="panel"><div class="panel-title"><h3>Full clearance by entity${metricHelpButton("Confirmed on-time %")}</h3><span>Not the percentage of open risk remediated</span></div><div id="${prefix}SlaSeverity"></div></article>
          <article class="panel"><div class="panel-title"><h3>Machine progress by reporting period${metricHelpButton("Status and progress")}</h3><span>Open and fully fixed machines</span></div><div id="${prefix}Movement"></div></article>
        </div>
      </section>
      <div class="subsection-heading"><div><h3>Remediation progress in the selected period</h3></div></div>
      <div id="${prefix}Progress" class="metric-grid"></div>
      <p class="management-definitions"><strong>Open:</strong> at least one machine/CVE pair is still open in the selected scope.
        <strong>Fully resolved:</strong> fixed in the period with nothing left open in the selected scope.
        Each machine and each CVE is counted once in its own total.
        Inactive devices stay open until they report again; they never count as fixed.
        Overdue counts are a subset of open.
        A CVE on 500 machines is one vulnerability, not 500 vulnerabilities.</p>
      <p class="coverage-note">Overdue means at least one unresolved exposure is past its policy SLA. Unknown deadlines are not treated as compliant.
        Status uses the selected snapshot and full workspace scope, not only changed rows or the exposure-status toggle.
        It does not certify resolution outside the selected filters. Earlier periods are reconstructed from retained lifecycle timestamps.</p>
      <article class="panel"><div class="panel-title"><h3>Period comparison</h3><span>Distinct entity totals, not added finding instances</span></div><div class="table-wrap"><table id="${prefix}ComparisonTable"></table></div></article>
      ${[["Machine","Machines"],["Cve","Vulnerabilities (unique CVEs)"],["Recommendation","Recommendations"]].map(([key,label])=>`
        <details class="management-detail"${key==="Recommendation"?" open":""}><summary>${label}: status and progress${metricHelpButton("Status and progress")}</summary>
          <div class="table-wrap"><table id="${prefix}${key}Table"></table></div>
        </details>`).join("")}`}
      ${view==="executive"?`<section id="${prefix}Detail" class="panel" hidden>
        <div class="panel-title"><h3>Records behind the selected count</h3></div>
        ${[["Machine","Machines"],["Cve","CVEs"],["Recommendation","Recommendations"]].map(([key,label])=>`<section data-management-table="${prefix}${key}Table" hidden><h4>${label}</h4><div class="table-wrap"><table id="${prefix}${key}Table"></table></div></section>`).join("")}
      </section>`:""}
    </section>`;
}

const FOUR_STATES=[["openWithin","Open – within SLA","open-within"],["openOverdue","Open – past SLA","open-past"],["completedWithin","Fixed – within SLA","fixed-within"],["completedLate","Fixed – past SLA","fixed-past"]];
function fourStateTotals(severity){
  const totals={openWithin:0,openOverdue:0,completedWithin:0,completedLate:0,noDeadline:0};
  for(const row of severity||[]){
    for(const [key] of FOUR_STATES)totals[key]+=Number(row[key])||0;
    totals.noDeadline+=(Number(row.unknownOpen)||0)+(Number(row.completedUnknown)||0);
  }
  return totals;
}
function fourStateTiles(severity,caption){
  const totals=fourStateTotals(severity);
  return `<div class="four-state-tiles" role="group" aria-label="Machine/CVE pairs by SLA state">${FOUR_STATES.map(([key,label,tone])=>`<div class="four-state-tile ${tone}"><span>${metricLabel(label)}</span><strong>${fmt(totals[key])}</strong></div>`).join("")}</div>
    <p class="coverage-note">${esc(caption)}${totals.noDeadline?` ${fmt(totals.noDeadline)} machine/CVE pairs have no SLA deadline and are not in these four states.`:""}</p>`;
}
function slaGaugeGrid(severity,periodLabel){
  const rows=new Map((severity||[]).map(row=>[row.label,row]));
  const empty={openWithin:0,openOverdue:0,completedWithin:0,completedLate:0,slaPercent:null};
  return ["Critical","High","Medium","Low"].map(label=>slaGauge({...empty,...rows.get(label),label})).join("")
    +`<p class="coverage-note">Within SLA % = (Open – within SLA + Fixed – within SLA) ÷ all machine/CVE pairs with a known deadline. Fixed pairs count when fixed in ${esc(periodLabel||"the selected period")}. Pairs without a deadline are excluded.</p>`;
}
function fourStateComparison(title,previous,current){
  const known=period=>period?.coverage==="complete"&&Array.isArray(period.severity);
  const value=(period,label,key)=>{if(!known(period))return null;const row=period.severity.find(item=>item.label===label);return row?Number(row[key])||0:0;};
  const span=period=>period?`${esc(period.label)}${period.start?` (${esc(period.start)} – ${esc(period.end)})`:""}`:"";
  const cell=(label,key)=>{
    const before=value(previous,label,key),after=value(current,label,key);
    if(before===null||after===null)return "<td>Waiting for data</td>";
    const change=after-before;
    return `<td>${fmt(before)} → <strong>${fmt(after)}</strong> <small class="four-state-change">(${change>0?"+":""}${fmt(change)})</small></td>`;
  };
  return `<article class="panel four-state-comparison"><div class="panel-title"><h3>${esc(title)}</h3><span>${span(previous)} → ${span(current)}</span></div>
    <div class="table-wrap"><table><thead><tr><th scope="col">Severity</th>${FOUR_STATES.map(([,label])=>`<th scope="col">${metricLabel(label)}</th>`).join("")}</tr></thead>
    <tbody>${["Critical","High","Medium","Low"].map(label=>`<tr><th scope="row">${label}</th>${FOUR_STATES.map(([key])=>cell(label,key)).join("")}</tr>`).join("")}</tbody></table></div>
    ${known(previous)&&known(current)?"":'<p class="coverage-note">Retained history does not fully cover both periods; the comparison is unavailable, not zero.</p>'}
    <p class="coverage-note">Machine/CVE pairs. Open counts are at each period end; fixed counts are fixes during each period.</p></article>`;
}
function managementPairPeriods(sla,periods){
  return (sla?.periods||[]).map((period,index)=>{
    const summary=periods?.[index]||{},range=String(summary.Range||"").replace(/ UTC$/,"").split(" - ");
    return {label:period.Period||summary.Period,start:range[0]||"",end:range[1]||"",coverage:summary.observed===false?"unavailable":"complete",severity:period.severity||[]};
  });
}

function slaGauge(row){
  const count=value=>Number.isSafeInteger(value)&&value>=0;
  if(!["openWithin","openOverdue","completedWithin","completedLate"].every(key=>count(row[key])))throw new Error("SLA gauge counts are incomplete. Retry the dashboard query.");
  const percent=typeof row.slaPercent==="number"&&Number.isFinite(row.slaPercent)?Math.max(0,Math.min(100,row.slaPercent)):null;
  const angle=Math.PI*(1-(percent??0)/100),x=60+50*Math.cos(angle),y=60-50*Math.sin(angle);
  const tone=percent===null?"var(--muted)":percent>=90?"var(--green)":percent>=70?"var(--amber)":"var(--red)";
  const arc=percent===null||percent===0?"":`<path d="M10 60 A50 50 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)}" fill="none" stroke="${tone}" stroke-width="12" stroke-linecap="round"/>`;
  const label=percent===null?"N/A":slaDashboardPercent(percent);
  return `<section class="sla-gauge severity-${esc(String(row.label).toLowerCase())}">
    <h4>${esc(row.label)}</h4>
    <svg viewBox="0 0 120 70" role="img" aria-label="${esc(`${row.label}: ${label} of machine/CVE pairs within SLA`)}"><path d="M10 60 A50 50 0 0 1 110 60" fill="none" stroke="var(--line)" stroke-width="12" stroke-linecap="round"/>${arc}<text x="60" y="56" text-anchor="middle">${esc(label)}</text></svg>
    <small>${esc(slaPolicyTarget(row.label))}</small>
    <ul>
      <li><span>${metricLabel("Open – within SLA")}</span><strong>${fmt(row.openWithin)}</strong></li>
      <li><span>${metricLabel("Open – past SLA")}</span><strong>${fmt(row.openOverdue)}</strong></li>
      <li><span>${metricLabel("Fixed – within SLA")}</span><strong>${fmt(row.completedWithin)}</strong></li>
      <li><span>${metricLabel("Fixed – past SLA")}</span><strong>${fmt(row.completedLate)}</strong></li>
    </ul>
  </section>`;
}

function renderManagementSla(view,sla,periods=null,charts=null){
  const prefix=view+"Management",root=$(prefix+"SlaStatus");
  const gauges=$(prefix+"SlaGauges");
  if(gauges&&sla?.periods?.[0])gauges.innerHTML=slaGaugeGrid(sla.periods[0].severity,sla.periods[0].Period);
  const pairs=managementPairPeriods(sla,periods);
  const tiles=$(prefix+"Tiles");
  if(tiles&&pairs[0])tiles.innerHTML=fourStateTiles(pairs[0].severity,`Machine/CVE pairs. Open at the end of ${pairs[0].label}; fixed during it.`);
  const comparison=$(prefix+"Comparison");
  if(comparison&&pairs.length>1)comparison.innerHTML=fourStateComparison(`${pairs[0].label} compared with ${pairs[1].label.toLowerCase()}`,pairs[1],pairs[0]);
  const totals=$(prefix+"PeriodTotals"),series=charts?.[prefix+"OpenFixed"];
  if(totals&&series?.totals){
    const past=fourStateTotals(pairs[0]?.severity).openOverdue;
    totals.innerHTML=`<div class="four-state-tiles" role="group" aria-label="Machine/CVE pairs in the selected period">
      <div class="four-state-tile neutral"><span>New machine/CVE pairs</span><strong>${fmt(series.totals.new)}</strong></div>
      <div class="four-state-tile fixed-within"><span>Fixed machine/CVE pairs</span><strong>${fmt(series.totals.fixed)}</strong></div>
      <div class="four-state-tile open-within"><span>Open at period end</span><strong>${fmt(series.totals.open)}</strong></div>
      <div class="four-state-tile open-past"><span>${metricLabel("Open – past SLA")} at period end</span><strong>${fmt(past)}</strong></div></div>
      <p class="coverage-note">${esc(series.start)} to ${esc(series.end)} UTC. New counts pairs first seen in the period; fixed counts pairs fully fixed in it.</p>`;
  }
  const rules=$(prefix+"PolicyRules");
  if(rules)rules.textContent=`${["Critical","High","Medium","Low"].map(severity=>`${severity} — ${slaPolicyTarget(severity)}`).join(" · ")}. The SLA clock starts at the collector's first observation on the machine, not the CVE publication date or a task due date. Open risk is within SLA through its recorded deadline; it is overdue after that deadline. Confirmed completion on or before the deadline is on time. Recorded deadlines take precedence; policy changes do not restart existing clocks.`;
  const snapshot=$(prefix+"LeadershipSnapshot");
  if(snapshot&&sla?.entityPeriods?.[0]){
    snapshot.innerHTML=(view==="executiveSnapshot"?unresolvedSeveritySnapshot(sla.entityPeriods[0]):"")+slaLeadershipSnapshot(sla.entityPeriods[0],sla.periods?.[0]?.Period||"Selected reporting period");
    if(view==="executiveSnapshot")bindSeverityVulnerabilityLinks(prefix+"LeadershipSnapshot");
  }
  if(!root||!sla)return;
  const current=sla.entityPeriods?.[0];
  if(!current){root.textContent="Entity-level SLA data is unavailable. Refresh after the Web App update is complete.";return;}
  const history=sla.history;
  root.innerHTML=`${[["cves","CVEs"],["machines","machines"]].map(([entity,unit])=>{
    const values=current[entity];return `<section class="sla-outcome-summary"><h4>${esc(unit==="CVEs"?"Distinct CVEs":"Distinct machines")}</h4>
      <strong>${fmt(values.totalOpen)} distinct open ${unit}</strong>
      <p>${fmt(values.openWithin)} open – within SLA · ${fmt(values.openOverdue)} open – past SLA · ${fmt(values.unknownOpen)} no SLA deadline.</p>
      <div class="sla-outcome-badges">
        <span class="sla-outcome-cleared">${fmt(values.confirmedFixes)} ${unit} fully cleared</span>
        <span class="sla-outcome-cleared">${fmt(values.completedWithin)} fixed – within SLA</span>
        <span class="sla-outcome-late">${fmt(values.completedLate)} fixed – past SLA</span>
        <span class="sla-outcome-unknown">${fmt(values.completedUnknown)} fixed – no SLA deadline</span>
      </div><p class="sla-outcome-rate">${esc(slaCompletionAssessment(values.completionPercent,values.confirmedFixes,unit))}.</p></section>`;
    }).join("")}
    <span>${esc(fixRecognitionDescription())} Observation dates are not exact patch-installation timestamps.</span>
    <span>Existing recorded deadlines remain in force; this deployment does not restart the SLA clock.
      Tracking updates when a new successful collection supplies evidence. Results are assessed at the pinned snapshot time.</span>
    ${history?.startUtc?`<span>Retained history begins ${esc(formatUtc(history.startUtc))} · ${fmt(history.snapshots)} recorded snapshots. Earlier CVE catalog dates are not machine-observation history.</span>`:"<span>Retained run-history coverage is unavailable; long-term SLA performance cannot be established.</span>"}
    ${sla.coverageGap?"<span>Coverage gap: some evidence has no machine or CVE identifier; incomplete evidence can limit remediation assessment.</span>":""}`;
  const policies=state.slaPolicy?.policies||[];
  $(prefix+"SlaPolicy").textContent=policies.length
    ?`Retained SLA policy: ${policies.map(policy=>`${policy.severity}${policy.knownExploitRequired?" + known exploit":""}: ${fmt(policy.slaDays)} days`).join(" · ")}. Deadlines are read from existing snapshot data.`
    :"Deadlines use existing snapshot data. A retained severity policy is unavailable; missing deadlines are not treated as compliant.";
}

function openDashboardDetail(selection,row={}){
  if(dashboardQuery.expired)return;
  const recommendationIds=state.detailRecommendationIds.slice();
  clearSelectedWorkItem();
  state.selectedEntity=selection;
  state.machineHistory.enabled=false;
  state.machineCveStatus="All";
  $("machineHistoryCards").innerHTML="";
  state.selectedRecommendationId=selection.type==="recommendation"?selection.id:"";
  state.pivotSourceLabel=state.activeView;
  if(selection.type==="recommendation"){
    state.recommendationsById.set(selection.id,row);
    state.detailRecommendationIds=recommendationIds.includes(selection.id)?recommendationIds:[selection.id];
  }
  dashboardQuery.detailTables.clear();
  const panel=$("pivotPanel");panel.hidden=false;panel.classList.add("fullscreen-mode");
  document.body.classList.add("pivot-detail-open");$("pivotBackdrop").hidden=false;
  $("pivotTitle").textContent="Loading selected item…";
  $("pivotSummary").textContent="";
  $("pivotCards").innerHTML="";$("pivotTable").innerHTML="";$("pivotDetails").innerHTML="";
  $("defenderRemediationLink").hidden=true;$("copyRecommendationReference").hidden=true;
  $("recommendationTrackingActions").hidden=true;$("recommendationCurrentStatus").hidden=true;
  void queryDashboardView("detail");
}

function prepareDashboardDetail(payload){
  const selection=state.selectedEntity;
  if(!selection)return;
  const record=payload.detail?.record||{},recommendation=selection.type==="recommendation",live=record.DataOrigin==="Live";
  if(recommendation)state.recommendationsById.set(selection.id,record);
  setPivotShell(`Selected: ${selection.type[0].toUpperCase()+selection.type.slice(1)}`,record.RecommendationName||record.DeviceName||record.CveId||selection.id,"",recommendation&&live,record);
  const ids=Object.keys(payload.tables||{}).filter(id=>id!=="pivotTable"),machine=selection.type==="machine";
  if(machine&&ids.includes("pivotRecommendationTable"))ids.unshift(...ids.splice(ids.indexOf("pivotRecommendationTable"),1));
  if(machine&&ids.includes("pivotMachineHistoryTable"))ids.unshift(...ids.splice(ids.indexOf("pivotMachineHistoryTable"),1));
  if(machine&&ids.includes("pivotSlaCveTable"))ids.unshift(...ids.splice(ids.indexOf("pivotSlaCveTable"),1));
  $("machineRemediation").hidden=!machine;
  if(machine){
    const progress=payload.metadata?.machineRemediation;
    const breakdown=progress?.openBreakdown,scan=progress?.scanBreakdown;
    $("machineCveStatus").value=state.machineCveStatus;
    $("machineRemediationProgress").innerHTML="";
    $("machineCveCounts").textContent=breakdown?`${fmt(progress.Open)} open = ${fmt(breakdown.withinSla)} within SLA + ${fmt(breakdown.pastSla)} past SLA${scan&&scan.inactive?` (${fmt(scan.inactive)} on inactive devices)`:""}. ${fmt(progress.resolved)} fixed this period.`:progress?"Open status breakdown unavailable. Reload after the Web App update.":"";
    $("machineRemediationContext").textContent=progress
      ?`${progress.label}: ${progress.start} to ${progress.end} UTC. The CVE list includes this machine's open CVEs even when opened from an activity count; workspace scope is preserved. Fixes are limited to this reporting period.`
      :"Machine remediation status unavailable. Update the Web App and reload this snapshot.";
  }
  $("machineHistoryControls").hidden=!machine;
  if(machine){
    const history=payload.metadata?.machineHistory,custom=state.machineHistory.period==="custom";
    const snapshotDate=String(dashboardQuery.snapshot.snapshotTimeUtc).slice(0,10);
    const defaultDates={start:shiftUtcDate(snapshotDate,1-({"7days":7,"30days":30,"90days":90}[state.machineHistory.period]||30)),end:snapshotDate};
    $("machineHistoryPeriod").value=state.machineHistory.period;
    for(const [id,key] of [["machineHistoryStart","start"],["machineHistoryEnd","end"]]){
      $(id).disabled=!custom;
      $(id).max=snapshotDate;
      $(id).value=(custom?state.machineHistory[key]:"")||history?.[key]||defaultDates[key];
    }
    $("machineHistoryContext").textContent=history
      ?`${history.start} through ${history.end} UTC. Each row is a CVE change on a machine, not a software/version record. Confirmed fixed requires all in-scope software evidence for that CVE to be cleared. Pending evidence is not fixed. ${history.coverage==="lifecycle-only"?"No matching retained events were available; only transitions supported by retained lifecycle timestamps can be shown.":"Retained events and lifecycle timestamps supply the history."} This is observed clearance, not an exact patch-installation audit. Reopened CVEs can also appear among previously cleared CVEs.`
      :"Load dated CVE additions, confirmed clearance, and reopened exposure for this machine. History is prepared only when requested.";
  }
  const titles={pivotMachineHistoryTable:"CVE additions, confirmed clearance, and reopened exposure",pivotSlaCveTable:"CVEs: confirmed fixed and still open",pivotManagementMachineTable:"Machines: remaining CVEs and SLA progress",pivotManagementCveTable:"Unique CVEs and affected-machine progress",pivotRecommendationTable:"Related recommendations",pivotCveTable:"CVE evidence",pivotFindingTable:"Exposure instance evidence"};
  renderPivotDetails(ids.map(id=>({id,title:titles[id]||headerLabel(id.replace(/^pivot/,"").replace(/Table$/,""))})));
  $("pivotDetails").insertAdjacentHTML(machine?"beforeend":"afterbegin",`<div class="server-record">${Object.entries(record).filter(([,value])=>value===null||typeof value!=="object").map(([key,value])=>`<div><small>${esc(headerLabel(key))}</small>${value===null?"Unknown":esc(displayDateTime(key,value))}</div>`).join("")}</div>`);
  const position=state.detailRecommendationIds.indexOf(selection.id);
  $("pivotPrevious").disabled=!recommendation||position<=0;
  $("pivotNext").disabled=!recommendation||position<0||position>=state.detailRecommendationIds.length-1;
  $("pivotPosition").textContent=recommendation&&position>=0?`${position+1} of ${state.detailRecommendationIds.length} recommendations on this results page`:"Snapshot-pinned detail";
  if(!recommendation&&(selection.type==="machine"||selection.type==="cve")){
    const href=selection.type==="machine"?defenderDeviceUrl({...record,DeviceId:record.DeviceId||selection.id}):DEFENDER_VULNERABILITIES_URL;
    $("pivotDetails").insertAdjacentHTML("afterbegin",`<p><a class="action-link" href="${esc(href)}" target="_blank" rel="noopener">Open ${esc(selection.type)} in Defender</a>${selection.type==="cve"?` · Search for ${esc(selection.id)}`:""}</p>`);
  }
  const trackingAvailable=recommendation&&state.recommendationTrackingEnabled&&(live||state.recommendationTrackingLocalPreview);
  $("recommendationTrackingActions").hidden=!trackingAvailable;$("recommendationCurrentStatus").hidden=!trackingAvailable;
  if(trackingAvailable)renderRecommendationTrackingStatus();
}

async function exportDashboardCsv(view=state.activeView,tableId=null){
  if(!dashboardQuery.snapshot||dashboardQuery.expired)return;
  const controller=new AbortController(),snapshotId=dashboardQuery.snapshot.snapshotId;
  dashboardQuery.exportControllers.add(controller);
  const request=dashboardRequest(view,tableId);
  dashboardStatus("Validating CSV export against the pinned snapshot…",false,false,true);
  try{
    const validation=await postDashboardQuery(request,{signal:controller.signal,isCurrent:()=>dashboardQuery.snapshot?.snapshotId===snapshotId&&!dashboardQuery.expired,onPreparing:()=>{
      dashboardStatus("Preparing exact export detail from the pinned snapshot. The download will start when it is ready.",false,false,true);
      $("retryDashboardQuery").hidden=true;
    }});
    if(tableId&&!validation.tables?.[tableId])throw new Error("The requested export detail is unavailable on this server. Retry after the dashboard update is complete.");
    if(tableId&&Number(validation.tables[tableId].total)===0){dashboardStatus("No matching rows to export for the selected filters.",false,false,true);return;}
    if(dashboardQuery.expired||dashboardQuery.snapshot?.snapshotId!==snapshotId)return;
    const frame=document.createElement("iframe"),started=Date.now();
    frame.name=`dashboard-export-${Date.now()}-${++dashboardQuery.exportSequence}`;frame.hidden=true;
    frame.title="CSV download response";
    frame.addEventListener("load",()=>{
      try{
        const text=frame.contentDocument?.body?.textContent?.trim();
        if(!text)return;
        const payload=JSON.parse(text),message=payload.detail||payload.error||"CSV export failed.";
        if(payload.status==="preparing"){
          if(Date.now()-started>120000){dashboardStatus("CSV export waited too long for capacity. Retry the export.");return;}
          dashboardStatus(message,false,false,true);
          setTimeout(submit,Math.max(1,Math.min(5,Number(payload.retryAfterSeconds)||2))*1000);
          return;
        }
        if(/snapshot expired|reload.*(?:snapshot|dashboard)|data changed/i.test(message))expireDashboardSnapshot();else dashboardStatus(message);
      }catch(error){dashboardStatus("The CSV download could not be completed. Check your sign-in and retry.");}
    });
    const submit=()=>{
      const form=document.createElement("form"),input=document.createElement("input");
      form.method="POST";form.action="/api/dashboard/export";form.target=frame.name;form.hidden=true;
      input.type="hidden";input.name="payload";input.value=JSON.stringify(request);form.appendChild(input);
      document.body.appendChild(form);form.submit();form.remove();
    };
    document.body.appendChild(frame);submit();
    dashboardStatus("CSV download requested for all matching rows, not just this page. Your browser streams the file directly.",false,false,true);
    // A successful attachment has no iframe document load event.
    setTimeout(()=>frame.remove(),300000);
  }catch(error){if(error.name!=="AbortError")dashboardStatus(error.message||"CSV export failed.");}
  finally{dashboardQuery.exportControllers.delete(controller);}
}

function renderFindingsList(){
  const result=dashboardQuery.tables.get("findingsTable"),last=Math.max(0,Math.ceil(Number(result?.total||0)/FINDINGS_PAGE_SIZE)-1);
  if(result&&findingsList.mode===$("findingsMode").value){
    const page=Math.max(0,Math.min(last,findingsList.page));
    if(page!==Math.floor(Number(result.offset||0)/FINDINGS_PAGE_SIZE)){void queryDashboardView(state.activeView,"findingsTable",page);return;}
  }
  render();
}
function renderTrend(){return render();}
function renderExecutiveSnapshot(){return render();}
function renderLifecycleReporting(){return render();}
function renderPivot(){if(state.selectedEntity)void queryDashboardView("detail");else $("pivotPanel").hidden=true;}
function pivotToRecommendation(row){return openDashboardDetail({type:"recommendation",id:String(row.RecommendationId||row.id||"")},row);}
function pivotToMachine(row){return openDashboardDetail({type:"machine",id:String(row.DeviceId||row.id||"")},row);}
function pivotToCve(row){return openDashboardDetail({type:"cve",id:normalizedCve(row.CveId||row.id||row)},typeof row==="object"?row:{});}
function showDetail(row){return dashboardRowAction(row.CveId?"cve":row.DeviceId?"machine":row.RecommendationId?"recommendation":"finding",row);}
function exportLifecycleCsv(){void exportDashboardCsv("trend","lifecycleDetailTable");}
function exportExecutiveSnapshotCsv(){void exportDashboardCsv("executiveSnapshot","executiveSnapshotManagement"+({machines:"Machine",cves:"Cve",recommendations:"Recommendation"}[state.executiveSnapshotUnit]||"Machine")+"Table");}
async function refreshRecommendationTracking(){
  const previous=JSON.stringify([...state.recommendationTracking]);
  const success=await loadRecommendationTracking();
  const changed=success&&previous!==JSON.stringify([...state.recommendationTracking]);
  if(changed)clearDashboardResponseCache();
  if(changed&&dashboardQuery.snapshot&&!dashboardQuery.expired){if(state.selectedEntity)void queryDashboardView("detail");else render();}
  return success;
}
$("retryDashboardQuery").addEventListener("click",async()=>{
  clearDashboardResponseCache();
  if(!dashboardQuery.snapshot)void startSnapshotDashboard();
  else{
    if(state.recommendationTrackingEnabled&&!await loadRecommendationTracking())return;
    if(state.selectedEntity)void queryDashboardView("detail");
    else render();
  }
});
$("reloadDashboardSnapshot").addEventListener("click",()=>location.reload());
$("exportFindingsCsv").addEventListener("click",()=>{void exportDashboardCsv("overview","findingsTable");});
loadDashboardDatasets();
