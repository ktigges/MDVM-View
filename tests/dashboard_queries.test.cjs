/**
 * Last modified: 2026-11-10
 * Purpose: Verify dashboard queries, metric explanations, and interactions.
 */

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../dashboard/app.js"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../dashboard/index.html"), "utf8");
const snapshotId = "a".repeat(64);
const snapshot = {snapshotId, runId:"run-1", snapshotTimeUtc:"2026-10-24T00:00:00Z", source:"local", slaPolicy:null};
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture({snapshotStatus=200, notices=[], now=null, preparation=null, trackingEnabled=false}={}) {
  const elements = new Map(), nodes = [], requests = [], timers = new Map();
  let timerId = 0;
  function node(id="") {
    const classes = new Set();
    const value = {
      id, dataset:{}, value:"", textContent:"", hidden:false, disabled:false,
      get innerHTML(){return this.markup||"";},
      set innerHTML(markup){this.markup=markup;for(const [,id] of markup.matchAll(/\bid="([^"]+)"/g))if(!elements.has(id))node(id);},
      listeners:{}, options:[], children:[], style:{setProperty(){},removeProperty(){}},
      classList:{add:(...names)=>names.forEach(name=>classes.add(name)),remove:(...names)=>names.forEach(name=>classes.delete(name)),contains:name=>classes.has(name),toggle(name,force){const next=force??!classes.has(name);if(next)classes.add(name);else classes.delete(name);return next;}},
      addEventListener(event,handler){(this.listeners[event]??=[]).push(handler);},
      dispatch(event,value){for(const handler of this.listeners[event]||[])handler({target:{value,checked:value},preventDefault(){},stopPropagation(){}});},
      setAttribute(key,value){this[key]=value;},removeAttribute(key){delete this[key];},
      querySelectorAll(selector){
        if(selector==="[data-vulnerability-severity]"||selector==="[data-remove-filter]"){
          const attribute=selector.slice(1,-1),key=attribute.slice(5).replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase());
          this.filterButtons=[...this.innerHTML.matchAll(new RegExp(`${attribute}="([^"]+)"`,"g"))].map(([,value])=>{const button=node();button.dataset[key]=value;return button;});
          return this.filterButtons;
        }
        if(selector.includes("table,"))return nodes.filter(item=>item.id.endsWith("Table")||item.id.endsWith("Cards")||item.id==="slaDashboardVisuals");
        if(selector==="tbody tr"){
          this.tableRows=[...this.innerHTML.matchAll(/<tr data-index="(\d+)"/g)].map(([,index])=>{const row=node();row.rowIndex=Number(index);return row;});
          return this.tableRows;
        }
        if(selector==="[data-query-page]"){
          this.pageButtons=[...this.innerHTML.matchAll(/data-query-page="(\d+)"([^>]*)/g)].map(([,page,attributes])=>{const button=node();button.dataset.queryPage=page;button.disabled=attributes.includes("disabled");return button;});
          return this.pageButtons;
        }
        if(selector===".cve-link"){
          this.cveButtons=[...this.innerHTML.matchAll(/class="cve-link"/g)].map((_,index)=>{const button=node();button.rowIndex=index;return button;});
          return this.cveButtons;
        }
        return [];
      },
      querySelector(selector){if(selector==="[data-query-export]")return this.exportButton??=node();return null;},
      contains(){return false;},appendChild(child){this.children.push(child);},
      closest(){return {dataset:{index:this.rowIndex||0}};},
      insertAdjacentHTML(position,markup){this.innerHTML=position==="afterbegin"?markup+this.innerHTML:this.innerHTML+markup;},
      insertAdjacentElement(_,child){elements.set(child.id,child);},
      scrollIntoView(){},scrollTo(){},focus(){},click(){this.dispatch("click");},remove(){elements.delete(this.id);},
      getBoundingClientRect(){return {top:0};},showModal(){this.open=true;},close(){this.open=false;},
      submit(){this.submitted=true;}
    };
    value.parentElement=value;
    nodes.push(value);
    if(id)elements.set(id,value);
    return value;
  }
  for(const [,id] of html.matchAll(/\bid="([^"]+)"/g))node(id);
  const views = ["executive","overview","workstations","recommendations","slaDashboard","sla","trend","executiveSnapshot","help"];
  const navigation = views.map(view=>{const button=node();button.dataset.view=view;button.textContent=view;if(view==="executive")button.classList.add("active");return button;});
  const pageButtons = ["first","previous","next","last"].map(action=>{const button=node();button.dataset.findingsPage=action;return button;});
  const activityButtons = attribute => [...html.matchAll(/<button [^>]+>/g)].map(([tag])=>{
    if(!tag.includes(`data-${attribute}=`))return null;
    const button=node();
    for(const [,key,value] of tag.matchAll(/data-([a-z-]+)="([^"]+)"/g))button.dataset[key.replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase())]=value;
    return button;
  }).filter(Boolean);
  const selectors = {
    ".story-nav button[data-view]":navigation,
    ".story-nav button,.story":[...navigation,...views.map(view=>elements.get(view))],
    ".story":views.map(view=>elements.get(view)),
    "[data-findings-page]":pageButtons,
    "[data-new-view]":activityButtons("new-view"),
    "[data-fixed-view]":activityButtons("fixed-view"),
  };
  const document = {
    body:node("body"),documentElement:node("root"),getElementById:id=>elements.get(id)||null,
    createElement:tag=>{const value=node();value.tagName=tag;return value;},addEventListener(){},
    querySelectorAll:selector=>selectors[selector]||[],
    querySelector(selector){
      if(selector===".story-nav button.active")return navigation.find(button=>button.classList.contains("active"));
      const view=selector.match(/data-view="([^"]+)"/)?.[1];
      return view?navigation.find(button=>button.dataset.view===view):node();
    }
  };
  const response = (payload,status=200) => ({ok:status>=200&&status<300,status,json:async()=>payload});
  const context = vm.createContext({
    document,console,AbortController,Set,Map,Date:now?class extends Date{static now(){return now();}}:Date,Number,URL:{createObjectURL:()=>"blob:test",revokeObjectURL(){}},
    window:{VULNERABILITY_VIEW_CONFIG:{},addEventListener(){},scrollTo(){},innerHeight:900},
    history:{},location:{pathname:"/",search:"",hash:"",reload(){context.reloaded=true;},assign(){}},
    localStorage:{getItem:()=>null,setItem(){}},matchMedia:()=>({matches:false}),
    navigator:{clipboard:{writeText:async()=>{}}},requestAnimationFrame:callback=>callback(),
    setTimeout(callback){const id=++timerId;timers.set(id,callback);return id;},clearTimeout:id=>timers.delete(id),
    fetch(url,options={}){
      const request={url,options,payload:options.body?JSON.parse(options.body):null};
      requests.push(request);
      if(url==="/api/dashboard/snapshot")return Promise.resolve(response(preparation?{status:"preparing",preparation,retryAfterSeconds:2}:{...snapshot,notices},snapshotStatus));
      if(url==="/api/dashboard/status")return Promise.resolve(response(preparation||{status:"ready"}));
      if(url==="/api/health")return Promise.resolve(response({recommendationTrackingEnabled:trackingEnabled}));
      if(url==="/api/auth")return Promise.resolve(response({enabled:false}));
      if(url==="/api/dashboard/query/cancel")return Promise.resolve(response({cancelled:true}));
      if(url.startsWith("/api/branding/logo"))return Promise.resolve(response({},404));
      return new Promise((resolve,reject)=>{request.resolve=(payload,status=200)=>resolve(response(payload,status));request.reject=reject;});
    },
  });
  vm.runInContext(source,context);
  return {
    context,elements,requests,selectors,pageButtons,response,
    run:code=>vm.runInContext(code,context),
    query:()=>requests.filter(request=>request.url==="/api/dashboard/query"),
    setSnapshotReady(){snapshotStatus=200;preparation=null;},
    setPreparation(value){preparation=value;},
    flushTimers(){const callbacks=[...timers.values()];timers.clear();callbacks.forEach(callback=>callback());},
    payload(overrides={}){return {snapshotId,snapshotTimeUtc:snapshot.snapshotTimeUtc,cards:{},texts:{},tables:{},donuts:{},slaGraphs:{},activity:{newFindings:15,newCves:5},scope:{detected:300,pending:5,recommendations:8},...overrides};}
  };
}

test("initial load pins metadata and requests only the summary, never full datasets or unpinned policy",async()=>{
  const app=fixture();await tick();
  assert.deepEqual(app.query().map(request=>request.payload.view),["executive"]);
  assert.equal(app.query()[0].payload.snapshotId,snapshotId);
  assert.equal(app.query()[0].payload.limit,100);
  assert.deepEqual(app.query()[0].payload.filters.recommendationTypes,["Vulnerability"]);
  assert.deepEqual(app.query()[0].payload.filters.domains,["Devices","Cloud"]);
  assert.ok(app.query()[0].payload.filters.workloadGrouping);
  assert.ok(!app.requests.some(request=>request.url.startsWith("/api/data/")||request.url==="/api/sla-policy"));
  app.query()[0].resolve(app.payload());await tick();
  assert.equal(app.elements.has("newFindingCount"),false);
  assert.equal(app.elements.get("newCveCount").textContent,"5");
  assert.equal(app.elements.get("loadingNotice").hidden,true);
});

test("dates use year-first local time and consistently labeled UTC timestamps",async()=>{
  const app=fixture();await tick();
  assert.match(app.run('formatLocal("2026-11-09T05:06:07Z")'),/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .+$/);
  assert.equal(app.run('formatUtc("2026-11-09T05:06:07Z")'),"2026-11-09 05:06:07 UTC");
  assert.equal(app.run('formatLocal("invalid")'),"Unknown local time");
  app.run('table("lifecycleHistoryTable",["SnapshotTimeUtc"],[{SnapshotTimeUtc:"2026-11-09T05:06:07Z"}])');
  assert.match(app.elements.get("lifecycleHistoryTable").innerHTML,/2026-11-09 05:06:07 UTC/);
  assert.equal(app.run('displayDateTime("OSVersion","1607")'),"1607");
});

test("expanded filters identify their fields and the Close Filter button collapses them",async()=>{
  const app=fixture();await tick();
  app.run("setFilterExpanded(false)");
  const saved=[];
  app.context.localStorage.setItem=(key,value)=>saved.push([key,value]);
  assert.equal(app.elements.get("filterBar").hidden,true);
  app.elements.get("filterToggle").dispatch("click");
  assert.equal(app.elements.get("filterBar").hidden,false);
  assert.equal(app.elements.get("filterToggle")["aria-expanded"],"true");
  assert.equal(app.elements.get("filterToggle").textContent,"Filters open");
  assert.match(html,/Workspace filter fields/);
  assert.match(html,/Scroll within this panel for more fields/);
  app.elements.get("closeFilter").dispatch("click");
  assert.equal(app.elements.get("filterBar").hidden,true);
  assert.equal(app.elements.get("filterToggle")["aria-expanded"],"false");
  assert.equal(app.elements.get("filterToggle").textContent,"Filters");
  assert.deepEqual(saved.at(-1),["vulnerability-view.filters-expanded.v2","false"]);
});

test("historical OS breakdown is independent of entity and travels with paging and exports",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("trend")');await tick();
  app.query().at(-1).resolve(app.payload());await tick();
  app.elements.get("reportingEntity").dispatch("change","machines");await tick();
  app.query().at(-1).resolve(app.payload());await tick();
  app.elements.get("reportingBreakdown").dispatch("change","osVersion");await tick();
  const request=app.query().at(-1);
  assert.equal(request.payload.filters.reportingEntity,"machines");
  assert.equal(request.payload.filters.reportingBreakdown,"osVersion");
  request.resolve(app.payload({tables:{lifecycleOsTable:{
    columns:["OSPlatform","OSVersion","New"],items:[{OSPlatform:"Windows11",OSVersion:"23H2",New:4}],
    total:1,offset:0,limit:100,action:"none",
  }}}));await tick();
  assert.equal(app.elements.get("lifecycleOsBreakdown").hidden,false);
  assert.match(app.elements.get("lifecycleOsTable").innerHTML,/Windows11/);
  assert.match(app.elements.get("lifecycleOsTable").innerHTML,/23H2/);
  const page=app.run('dashboardRequest("trend","lifecycleOsTable",1)');
  assert.equal(page.filters.reportingBreakdown,"osVersion");
  assert.equal(page.filters.reportingEntity,"machines");
  const exported=app.run('dashboardRequest("trend","lifecycleDetailTable")');
  assert.equal(exported.filters.reportingBreakdown,"osVersion");
  app.elements.get("reportingBreakdown").dispatch("change","All");await tick();
  app.query().at(-1).resolve(app.payload());await tick();
  assert.equal(app.elements.get("lifecycleOsBreakdown").hidden,true);
});

test("startup polls index preparation without rendering partial findings",async()=>{
  const app=fixture({
    snapshotStatus:202,
    preparation:{status:"preparing",datasetRows:{findings:1837575},progress:{stage:"load-rows:findings",rows:204000,elapsedSeconds:60}},
  });
  await tick();
  assert.equal(app.query().length,0);
  assert.match(app.elements.get("loadingNotice").innerHTML,/Rebuilding findings index/);
  assert.match(app.elements.get("loadingNotice").innerHTML,/204,000 \/ 1,837,575 rows/);
  assert.match(app.elements.get("loadingNotice").innerHTML,/<strong>Preparing dashboard data indexes<\/strong>/);
  assert.match(app.elements.get("loadingNotice").innerHTML,/<span>May follow a server restart, first load, or new snapshot\.<\/span>/);
  assert.doesNotMatch(app.elements.get("loadingNotice").innerHTML,/Complete results will appear|Partial findings are not shown|Completion percentage|remaining time are not reported/);
  app.setSnapshotReady();
  app.flushTimers();await tick();
  assert.equal(app.query().length,1);
  assert.equal(app.query()[0].payload.view,"executive");
  app.query()[0].resolve(app.payload());await tick();
  assert.equal(app.elements.get("loadingNotice").hidden,true);
});

test("startup names shared aggregate preparation without showing partial totals",async()=>{
  const app=fixture({snapshotStatus:202,preparation:{
    status:"preparing",progress:{stage:"read-model:recommendation-relationships",elapsedSeconds:61,stageSeconds:8},
  }});
  await tick();
  const notice=app.elements.get("loadingNotice").innerHTML;
  assert.match(notice,/Preparing shared dashboard aggregates: recommendation relationships/);
  assert.match(notice,/61s elapsed/);
  assert.match(notice,/8s in current stage/);
  assert.match(notice,/May follow a server restart, first load, or new snapshot/);
  assert.doesNotMatch(notice,/Complete results will appear|Partial findings are not shown/);
  assert.equal(app.query().length,0);
});

test("startup distinguishes persistent cache reuse from rebuilding",async()=>{
  const app=fixture({snapshotStatus:202,preparation:{
    status:"preparing",progress:{stage:"viewer-cache:restore-primary",processedBytes:10485760,elapsedSeconds:12},
  }});
  await tick();
  const notice=app.elements.get("loadingNotice").innerHTML;
  assert.match(notice,/Restoring persistent query indexes/);
  assert.match(notice,/10.0 MiB/);
  assert.doesNotMatch(notice,/Rebuilding/);
  assert.equal(app.query().length,0);
});

test("index restore and preparation errors remain visible while retrying",async()=>{
  const app=fixture({snapshotStatus:202,preparation:{
    status:"error",error:"Snapshot preparation failed. Retrying automatically.",
    progress:{stage:"restore-query-index",processedBytes:10485760,elapsedSeconds:12},
  }});
  await tick();
  assert.match(app.elements.get("loadingNotice").innerHTML,/retry scheduled/);
  assert.doesNotMatch(app.elements.get("loadingNotice").innerHTML,/May follow a server restart|<span><\/span>/);
  assert.match(app.elements.get("loadingNotice").innerHTML,/Restoring published data index/);
  assert.match(app.elements.get("loadingNotice").innerHTML,/10.0 MiB/);
  assert.equal(app.query().length,0);
});

test("replacement status preserves the pinned results and exposes preparation stats",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload({texts:{filterCount:"complete results"}}));await tick();
  const pinnedCount=app.elements.get("filterCount").textContent;
  assert.match(pinnedCount,/detected CVEs.*CVEs awaiting verification.*recommendations/);
  assert.notEqual(pinnedCount,"complete results");
  app.setPreparation({status:"preparing",readySnapshotId:snapshotId,progress:{stage:"validate-query-index",elapsedSeconds:4}});
  app.flushTimers();await tick();
  const notice=app.elements.get("dashboardPreparationStatus");
  assert.equal(notice.hidden,false);
  assert.match(notice.textContent,/Serving the previous complete snapshot/);
  assert.match(notice.textContent,/Validating published data index/);
  assert.equal(app.run("dashboardQuery.snapshot.snapshotId"),snapshotId);
  assert.equal(app.elements.get("filterCount").textContent,pinnedCount);
  assert.equal(app.query().length,1);
});

test("cold report polling displays the actual per-query index stage",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({
    snapshotId,status:"preparing",retryAfterSeconds:2,
    progress:{stage:"load-rows:finding-events",rows:12000,elapsedSeconds:8},
  },202);await tick();
  assert.match(app.elements.get("loadingNotice").innerHTML,/Rebuilding finding-events index/);
  assert.match(app.elements.get("loadingNotice").innerHTML,/12,000 rows/);
});

test("Summary query phases use visible view names and do not block navigation",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({
    snapshotId,status:"preparing",retryAfterSeconds:2,
    progress:{stage:"query:executive:recommendation-details",elapsedSeconds:15},
  },202);await tick();
  assert.match(app.elements.get("loadingNotice").innerHTML,/Preparing Summary: recommendation evidence/);
  app.run('activateView("recommendations")');await tick();
  assert.equal(app.query().at(-1).payload.view,"recommendations");
  app.query().at(-1).resolve(app.payload());await tick();
  assert.equal(app.elements.get("loadingNotice").hidden,true);
});

test("workflow preparation has explicit progress instead of a generic blocked response",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({
    snapshotId,status:"preparing",retryAfterSeconds:2,
    progress:{stage:"recommendation-tracking-read",elapsedSeconds:15},
  },202);await tick();
  assert.match(app.elements.get("loadingNotice").innerHTML,/Reading recommendation workflow state/);
  assert.match(app.run('dashboardPreparationText({progress:{stage:"query:executive:tracking"}})'),/Preparing Summary: recommendation workflow state/);
  assert.match(app.run('dashboardPreparationText({progress:{stage:"query:detail:detail-workloads"}})'),/Preparing Selected item: affected workloads/);
  assert.match(app.run('dashboardPreparationText({progress:{stage:"query:detail:detail-evidence"}})'),/Preparing Selected item: finding evidence page/);
});

test("report preparation shows numbered server phases and what remains",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({
    snapshotId,status:"preparing",retryAfterSeconds:2,
    progress:{stage:"query:trend:shared-clocks",elapsedSeconds:30,stageSeconds:12,phasePlan:{
      steps:["query-workflow","query-scope","report-clocks","report-periods","report-risk","report-daily","report-weekly","report-history","query-finalize"],
      currentStep:3,totalSteps:9,
    }},
  },202);await tick();
  const markup=app.elements.get("loadingNotice").innerHTML;
  assert.match(markup,/Step 3 of 9: Calculate finding lifecycle dates/);
  assert.match(markup,/Next: Summarize reporting periods/);
  assert.match(markup,/6 phases after this/);
  assert.match(markup,/aria-current="step"/);
  assert.match(markup,/Calculate weekly remediation — remaining/);
  assert.match(markup,/Finalize report response — remaining/);
  assert.match(markup,/finding lifecycle dates \(first seen, fixed, reopened and SLA due\)/);
  assert.match(markup,/Phase counts do not estimate remaining time/);
  assert.doesNotMatch(markup,/aria-valuenow|aria-valuemax|shared-clocks/);
  assert.match(app.run('dashboardPreparationText({progress:{stage:"query:detail:detail-cves",phasePlan:{steps:["query-scope","detail-cves","query-finalize"],currentStep:2,totalSteps:3}}})'),/Step 2 of 3/);
});

test("snapshot preparation shows its server phase plan and escapes labels",async()=>{
  const app=fixture({snapshotStatus:202,preparation:{status:"preparing",progress:{
    stage:"viewer-cache:publish-primary",phasePlan:{
      steps:["snapshot-indexes","snapshot-aggregates","snapshot-search","snapshot-reports","snapshot-publication"],
      currentStep:5,totalSteps:5,
    },
  }}});
  await tick();
  const markup=app.elements.get("loadingNotice").innerHTML;
  assert.match(markup,/Step 5 of 5: Save reusable viewer caches/);
  assert.match(markup,/Final phase/);
  const escaped=app.run('dashboardPhasePlanMarkup({phasePlan:{steps:["<bad>"],currentStep:1,totalSteps:1},failure:{stage:"failed"}})');
  assert.match(escaped,/&lt;bad&gt;/);
  assert.match(escaped,/failed/);
  assert.doesNotMatch(escaped,/<bad>/);
  assert.equal(app.run('dashboardPhasePlanMarkup({phasePlan:{steps:["one"],currentStep:2,totalSteps:1}})'),"");
});

test("initial tracking refresh does not abort and restart the selected report",async()=>{
  const app=fixture({trackingEnabled:true});await tick();
  const initial=app.query()[0];
  const reads=app.requests.filter(request=>request.url.startsWith("/api/recommendation-tracking"));
  assert.ok(reads.length);
  for(const read of reads)read.resolve({items:[]});
  await tick();
  assert.equal(app.query().length,1);
  assert.equal(initial.options.signal.aborted,false);
  initial.resolve(app.payload());await tick();
  assert.equal(app.elements.get("loadingNotice").hidden,true);
});

test("unchanged workflow refresh preserves cached analytics without resubmitting a report",async()=>{
  const app=fixture({trackingEnabled:true});await tick();
  for(const read of app.requests.filter(request=>request.url.startsWith("/api/recommendation-tracking")))read.resolve({items:[]});
  await tick();
  app.query()[0].resolve(app.payload());await tick();
  const count=app.query().length,size=app.run("dashboardQuery.responses.size");
  const refresh=app.run("refreshRecommendationTracking()");
  app.requests.filter(request=>request.url.startsWith("/api/recommendation-tracking")).at(-1).resolve({items:[]});
  assert.equal(await refresh,true);
  assert.equal(app.query().length,count);
  assert.equal(app.run("dashboardQuery.responses.size"),size);
});

test("per-index status lists complete, active and waiting steps without pretending to know percent",async()=>{
  const progress={
    stage:"build-index:findings:2/3:findings_Severity",stageSeconds:29,elapsedSeconds:700,
    indexPlan:{dataset:"findings",steps:["findings_FindingKey","findings_Severity","findings_priority","ANALYZE"],completedSteps:1,totalSteps:4},
  };
  const app=fixture({snapshotStatus:202,preparation:{status:"preparing",progress}});
  await tick();
  const markup=app.elements.get("loadingNotice").innerHTML;
  assert.match(markup,/Building findings index 2\/3: findings_Severity/);
  assert.match(markup,/1 \/ 4 index preparation steps complete/);
  assert.match(markup,/29s in current stage/);
  assert.match(markup,/<details[^>]+data-index-plan/);
  assert.match(markup,/findings_FindingKey — complete/);
  assert.match(markup,/findings_Severity — in progress/);
  assert.match(markup,/findings_priority — waiting/);
  assert.match(markup,/ANALYZE — waiting/);
  assert.doesNotMatch(markup,/aria-valuenow|aria-valuemax/);
});

test("a failed index remains named in preparation status and its plan is escaped",async()=>{
  const app=fixture({snapshotStatus:202,preparation:{status:"error",error:"Retry scheduled.",progress:{
    stage:"failed",failure:{stage:"build-index:findings:1/1:<bad>",indexPlan:{
      dataset:"findings",steps:["<bad>","ANALYZE"],completedSteps:0,totalSteps:2,
    }},
  }}});
  await tick();
  const markup=app.elements.get("loadingNotice").innerHTML;
  assert.match(markup,/Building findings index 1\/1: &lt;bad&gt;/);
  assert.match(markup,/&lt;bad&gt; — failed/);
  assert.match(markup,/ANALYZE — waiting/);
  assert.ok(!markup.includes("<bad>"));
});

test("a completed replacement invites reload without mixing snapshots",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.setPreparation({status:"ready",readySnapshotId:"b".repeat(64)});
  app.flushTimers();await tick();
  assert.match(app.elements.get("dashboardPreparationStatus").textContent,/newer complete snapshot is ready/);
  assert.equal(app.run("dashboardQuery.snapshot.snapshotId"),snapshotId);
  assert.equal(app.query().length,1);
});

test("report progress is indeterminate and its elapsed clock does not issue extra requests",async()=>{
  let now=1000;
  const app=fixture({now:()=>now});await tick();
  const notice=app.elements.get("loadingNotice");
  assert.match(notice.innerHTML,/role="progressbar"/);
  assert.match(notice.innerHTML,/Waiting for server response/);
  assert.doesNotMatch(notice.innerHTML,/Completion percentage|completion percentage unavailable|remaining time are not reported/);
  assert.doesNotMatch(html,/Completion percentage|completion percentage unavailable|remaining time are not reported/);
  assert.doesNotMatch(notice.innerHTML,/aria-valuenow|aria-valuemax/);
  assert.equal(app.elements.get("reportProgressElapsed").textContent,"Elapsed 0:00");
  now+=61000;
  app.flushTimers();await tick();
  assert.equal(app.elements.get("reportProgressElapsed").textContent,"Elapsed 1:01");
  assert.equal(app.query().length,1);
  app.query()[0].resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  assert.match(notice.innerHTML,/Server preparation pending · 1 status check/);
  assert.equal(app.elements.get("reportProgressElapsed").textContent,"Elapsed 1:01");
  now+=9000;
  app.flushTimers();await tick();
  assert.equal(app.elements.get("reportProgressElapsed").textContent,"Elapsed 1:10");
  assert.equal(app.query().length,2);
  assert.equal(app.query()[1].options.body,app.query()[0].options.body);
  app.query()[1].resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  assert.match(notice.innerHTML,/Server preparation pending · 2 status checks/);
  app.flushTimers();await tick();
  app.query().at(-1).resolve(app.payload());await tick();
  assert.equal(notice.hidden,true);
  assert.equal(app.run("dashboardVisualProgress.timer"),null);
  now+=60000;
  app.flushTimers();await tick();
  assert.equal(app.query().length,3);
  assert.equal(app.elements.get("reportProgressElapsed").textContent,"Elapsed 1:10");
});

test("changing report views resets visual progress without retaining a cancelled poll",async()=>{
  let now=1000;
  const app=fixture({now:()=>now});await tick();
  now+=4000;
  app.query()[0].resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  assert.match(app.elements.get("loadingNotice").innerHTML,/1 status check/);
  app.run('activateView("trend")');await tick();
  assert.equal(app.elements.get("reportProgressElapsed").textContent,"Elapsed 0:00");
  assert.match(app.elements.get("loadingNotice").innerHTML,/Waiting for server response/);
  assert.equal(app.run("dashboardVisualProgress.checks"),0);
  app.flushTimers();await tick();
  assert.equal(app.query().length,2);
  app.query().at(-1).resolve(app.payload());await tick();
  assert.equal(app.run("dashboardVisualProgress.timer"),null);
});

test("scope ring stays active after the yellow overlay closes until the result arrives",async()=>{
  const app=fixture();await tick();
  const indicator=app.elements.get("scopeBusyIndicator"),scope=app.elements.get("scopeProgress");
  assert.equal(indicator.hidden,false);
  assert.equal(scope["aria-busy"],"true");
  assert.equal(scope.classList.contains("is-loading"),true);
  assert.match(app.elements.get("filterCount").textContent,/Loading matching scope/);
  app.run("hideDashboardLoadingNotice()");
  assert.equal(app.elements.get("loadingNotice").hidden,true);
  assert.equal(indicator.hidden,false);
  app.query()[0].resolve(app.payload());await tick();
  assert.equal(indicator.hidden,true);
  assert.equal(scope["aria-busy"],"false");
  assert.equal(scope.classList.contains("is-loading"),false);
  const heading=html.slice(html.indexOf('id="scopeProgress"'),html.indexOf('class="quick-filters"'));
  assert.match(heading,/id="loadingNotice"/);
  assert.match(heading,/id="scopeBusyIndicator"/);
});

test("the scope ring waits for both the main view and the selected item",async()=>{
  const app=fixture();await tick();
  app.run('pivotToMachine({DeviceId:"machine-x"})');await tick();
  const detail=app.query().at(-1);
  app.query()[0].resolve(app.payload());await tick();
  assert.equal(app.elements.get("scopeBusyIndicator").hidden,false);
  assert.equal(app.elements.get("loadingNotice").hidden,false);
  detail.resolve(app.payload({detail:{record:{DeviceId:"machine-x"}}}));await tick();
  assert.equal(app.elements.get("scopeBusyIndicator").hidden,true);
  assert.equal(app.elements.get("loadingNotice").hidden,true);
});

test("closing a loading item cancels its query and stops the scope ring",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToMachine({DeviceId:"machine-x"})');await tick();
  const detail=app.query().at(-1);
  assert.equal(app.elements.get("scopeBusyIndicator").hidden,false);
  app.elements.get("clearPivot").click();await tick();
  assert.equal(detail.options.signal.aborted,true);
  assert.equal(app.elements.get("scopeBusyIndicator").hidden,true);
  assert.equal(app.elements.get("loadingNotice").hidden,true);
});

test("failed scope requests stop the animation but keep stale results hidden and errors visible",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({detail:"Scope preparation failed"},500);await tick();
  assert.equal(app.elements.get("scopeBusyIndicator").hidden,true);
  assert.equal(app.elements.get("loadingNotice").hidden,true);
  assert.equal(app.elements.get("executive")["aria-busy"],"true");
  assert.equal(app.elements.get("dashboardQueryStatus").hidden,false);
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/Scope preparation failed/);
});

test("snapshot startup failures do not leave a processing animation running",async()=>{
  const app=fixture({snapshotStatus:500});await tick();
  assert.equal(app.elements.get("scopeBusyIndicator").hidden,true);
  assert.equal(app.elements.get("scopeProgress")["aria-busy"],"false");
  assert.equal(app.elements.get("dashboardQueryStatus").hidden,false);
});

test("shared activity tiles put full-width labels before their counts",()=>{
  const tiles=[...html.matchAll(/<button\b[^>]*data-(?:new|fixed)-view=[^>]*>(.*?)<\/button>/g)];
  assert.equal(tiles.length,6);
  for(const [,markup] of tiles)assert.match(markup,/^<span>[^<]+<\/span><strong id="[^"]+">0<\/strong><small [^>]+>[^<]+<\/small>$/);
  const css=fs.readFileSync(path.join(__dirname,"../dashboard/styles.css"),"utf8");
  assert.match(css,/\.new-activity-metrics button,\.new-activity-metrics \.window-metric\{[^}]*grid-template-columns:minmax\(0,1fr\)/);
});

test("activity tiles explain counts and partial fixes in plain language on hover and focus",()=>{
  const tiles=[...html.matchAll(/<button\b([^>]*data-(new|fixed)-view=[^>]*)>(.*?)<\/button>/g)];
  assert.equal(tiles.length,6);
  for(const [,attributes,kind,markup] of tiles){
    const helpId=attributes.match(/aria-describedby="([^"]+)"/)?.[1];
    assert.ok(helpId);
    assert.ok(markup.includes(`<small id="${helpId}" class="activity-metric-help" role="tooltip">`));
    assert.match(markup,/selected dates/);
    assert.match(markup,/loaded collection and your filters/);
    assert.doesNotMatch(markup,/non-empty|FirstObservedUtc|FirstSeenUtc|EffectiveRemediationUtc|FixedUtc|DeviceId|RecommendationId|pinned snapshot/i);
    if(kind==="fixed"){
      assert.match(markup,/awaiting.*confirm/);
      assert.match(markup,/except the detected\/fixed filter/);
    }
  }
  assert.match(html,/same CVE on 100 machines counts once/);
  assert.match(html,/not necessarily new machines/);
  assert.match(html,/existing recommendation can appear here/);
  assert.match(html,/vulnerability may remain on other machines or software versions/);
  assert.match(html,/does not mean the machine is fully fixed/);
  assert.match(html,/does not mean the recommendation is finished/);
  const css=fs.readFileSync(path.join(__dirname,"../dashboard/styles.css"),"utf8");
  assert.match(css,/button:hover \.activity-metric-help,\.new-activity-metrics button:focus-visible \.activity-metric-help\{display:block\}/);
  for(const selector of [/\.lifecycle-tooltip::after\{([^}]+)\}/,/\.new-activity-metrics \.activity-metric-help\{([^}]+)\}/]){
    const style=css.match(selector)?.[1];
    assert.ok(style);
    assert.match(style,/background:#fff4cc;color:#33270a/);
    assert.match(style,/border:1px solid #b7791f/);
  }
});

test("entity tiles place distinct CVE labels above their values",async()=>{
  const app=fixture();await tick();
  app.run('cards("pivotCards",[[14009,"Distinct active CVEs"]])');
  assert.match(app.elements.get("pivotCards").innerHTML,/>Distinct active CVEs <button[^>]+data-help-key="Distinct active CVEs"[^>]*>\?<\/button><\/span><strong class="value">14,009<\/strong>/);
});

test("recommendation activity distinguishes observed progress from confirmed clearance",()=>{
  const tile=html.match(/<button\b[^>]*aria-describedby="fixedRecommendationHelp"[^>]*>(.*?)<\/button>/)?.[1];
  assert.ok(tile);
  assert.match(tile,/<span>recommendations with observed progress<\/span>/);
  assert.match(tile,/recommendation counts once when at least one linked remediation observation/);
  assert.match(tile,/not the same as confirmed Improved or Fully resolved/);
  assert.match(tile,/Software and version records are supporting evidence, not additional vulnerabilities to count/);
  assert.match(tile,/awaiting confirmation/);
  assert.match(tile,/same CVE may remain on the machine or other machines/);
  assert.match(tile,/does not mean the recommendation is finished/);
});

test("vulnerability count help explains distinct CVEs without offering instance metrics",async()=>{
  const app=fixture();await tick();
  const help=app.run('metricHelp("Distinct active CVEs")');
  assert.match(help,/Each CVE is counted once, even across many devices, products, or versions/);
  assert.match(help,/filtered snapshot/);
  app.run('cards("pivotCards",[[100,"Distinct active CVEs"]])');
  assert.match(app.elements.get("pivotCards").innerHTML,/title="[^"]*Each CVE is counted once/);
  assert.match(app.elements.get("pivotCards").innerHTML,/<button[^>]+aria-label="Explain Distinct active CVEs" aria-haspopup="dialog"/);
  assert.match(html,/<select id="findingsMode" aria-describedby="findingInstancesHelp"/);
  assert.match(html,/<details class="finding-count-help"><summary>How vulnerabilities are counted<\/summary><p id="findingInstancesHelp">/);
  assert.match(html,/supporting evidence, not additional vulnerabilities/);
  assert.doesNotMatch(html,/<option value="findings">/);
  assert.doesNotMatch(html,/technical-metric|TechnicalEvidence|trendWorkflowEvidence|finding-instance evidence/);
});

test("entity help distinguishes CVE and machine counts from recommendation workload",async()=>{
  const app=fixture();await tick();
  assert.equal(app.run('metricHelp("Active exposure instances")'),"");
  assert.match(app.run('metricHelp("Machines with detections")'),/Distinct devices/);
  assert.match(app.run('metricHelp("Related recommendations")'),/many CVEs on many machines/);
  const cves=app.run('metricHelp("Distinct active CVEs")');
  assert.match(cves,/combines CVEs across all its matching devices/);
  assert.match(cves,/an individual device can have fewer/);
  assert.match(html,/counts each CVE once across all matching machines/);
});

test("report progress respects reduced motion and marks elapsed updates as non-announcing",()=>{
  const css=fs.readFileSync(path.join(__dirname,"../dashboard/styles.css"),"utf8");
  assert.match(css,/@media\(prefers-reduced-motion:reduce\)\{\.report-progress-indicator\{animation:none/);
  assert.match(html,/id="reportProgressElapsed" aria-live="off"/);
});

test("missing CVE metadata shows unavailable details and unknown scores without hiding findings",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  const missing={CveId:"CVE-2026-61359",CveMetadataStatus:"Unavailable",Severity:"High",CvssScore:null,PublicExploitAvailable:null,VerifiedExploitAvailable:null};
  app.context.missing=missing;
  assert.equal(app.run('cell("CvssScore",null,missing)'),"Unknown");
  assert.equal(app.run('cell("KnownExploit",null,missing)'),"Unknown");
  assert.match(app.run('cell("CveMetadataStatus","Unavailable",missing)'),/Details unavailable/);
  app.run('activateView("overview")');
  app.query().at(-1).resolve(app.payload({
    tables:{findingsTable:{columns:["CveId","CvssScore","CveMetadataStatus"],items:[missing],total:1,offset:0,limit:100,action:"cve"}},
  }));await tick();
  assert.match(app.elements.get("findingsTable").innerHTML,/CVE-2026-61359/);
  assert.match(app.elements.get("findingsTable").innerHTML,/Details unavailable/);
  assert.match(app.elements.get("findingsTable").innerHTML,/Unknown/);
});

test("primary navigation clears selected work items and closes detail panels before requesting the next view",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('state.selectedRecommendationId="rec-a";state.detailRecommendationIds=["rec-a"];state.selectedEntity={type:"machine",id:"machine-a"};state.selectedCveDialogId="CVE-2026-1234";state.pivotSourceLabel="Selected machine";document.body.classList.add("pivot-detail-open");$("pivotPanel").hidden=false;$("machineHistoryControls").hidden=false;activateView("workstations")');
  for(const key of ["selectedRecommendationId","selectedCveDialogId","pivotSourceLabel"])assert.equal(app.run(`state.${key}`),"");
  assert.equal(app.run("state.detailRecommendationIds.length"),0);
  assert.equal(app.run("state.selectedEntity"),null);
  assert.equal(app.run('document.body.classList.contains("pivot-detail-open")'),false);
  assert.equal(app.elements.get("pivotPanel").hidden,true);
  assert.equal(app.elements.get("machineHistoryControls").hidden,true);
  assert.equal(app.query().at(-1).payload.view,"workstations");
  assert.equal(app.query().at(-1).payload.selection,undefined);
});

test("navigation lazily requests just the selected view and ignores aborted stale responses",async()=>{
  const app=fixture();await tick();
  const first=app.query()[0];
  app.run('activateView("workstations")');
  const second=app.query()[1];
  assert.equal(first.options.signal.aborted,true);
  assert.equal(second.payload.view,"workstations");
  second.resolve(app.payload({texts:{workstationCards:"current view"}}));await tick();
  first.resolve(app.payload({texts:{workstationCards:"stale summary"}}));await tick();
  assert.equal(app.elements.get("workstationCards").textContent,"current view");
  assert.equal(app.elements.get("loadingNotice").hidden,true);
});

test("returning to an unchanged view renders immediately without another request or loading cycle",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload({texts:{newActivityContext:"prepared summary"}}));await tick();
  app.run('activateView("overview")');
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{columns:["CveId"],items:[{CveId:"CVE-CACHED"}],total:1,offset:0,limit:100,action:"cve"}}}));await tick();
  const count=app.query().length;
  app.run('activateView("executive")');
  assert.equal(app.query().length,count);
  assert.equal(app.elements.get("newActivityContext").textContent,"prepared summary");
  assert.equal(app.elements.get("loadingNotice").hidden,true);
  app.run('activateView("overview")');
  assert.equal(app.query().length,count);
  assert.ok(app.elements.get("findingsTable").innerHTML.includes("CVE-CACHED"));
  assert.equal(app.elements.get("loadingNotice").hidden,true);
  app.elements.get("severityFilter").dispatch("change","Critical");
  assert.equal(app.query().length,count+1);
  assert.equal(app.query().at(-1).payload.filters.severity,"Critical");
});

test("browser view results stay bounded and cannot survive snapshot expiration",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('for(let i=0;i<30;i++)cacheDashboardResponse(String(i),{text:"cached"});');
  assert.equal(app.run("dashboardQuery.responses.size"),16);
  assert.ok(app.run("dashboardQuery.responseBytes")<=8*1024*1024);
  app.run('cacheDashboardResponse("too-large",{text:"x".repeat(2*1024*1024)});');
  assert.equal(app.run('dashboardQuery.responses.has("too-large")'),false);
  app.run("expireDashboardSnapshot()");
  assert.equal(app.run("dashboardQuery.responses.size"),0);
  assert.equal(app.run("dashboardQuery.responseBytes"),0);
});

test("machine detail shows distinct active and pending CVEs without software-record counts",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToMachine({DeviceId:"machine-1",DeviceName:"example-ws11"})');
  app.query().at(-1).resolve(app.payload({
    detail:{type:"machine",id:"machine-1",record:{DeviceId:"machine-1",DeviceName:"example-ws11"}},
    cards:{pivotCards:[[165,"Distinct active CVEs"],[150,"CVEs with pending evidence"],[1,"Workloads with detections"]]},
    texts:{pivotSummary:"165 distinct active CVEs · 150 CVEs with pending evidence, excluded from active totals."},
    tables:{pivotCveTable:{columns:["FindingStatus","CveId"],items:[{FindingStatus:"PendingVerification",CveId:"CVE-PENDING"}],total:300,offset:0,limit:100,action:"cve",rowLabel:"CVEs"}},
  }));await tick();
  assert.ok(app.elements.get("pivotCards").innerHTML.includes("Distinct active CVEs"));
  const cards=app.elements.get("pivotCards").innerHTML;
  assert.doesNotMatch(cards,/exposure instances|finding instances|evidence rows/i);
  assert.equal((cards.match(/data-help-key=/g)||[]).length,3);
  assert.equal((cards.match(/aria-haspopup="dialog"/g)||[]).length,3);
  assert.match(cards,/counts can overlap/);
  assert.match(cards,/grouping combines multiple instances/);
  const css=fs.readFileSync(path.join(__dirname,"../dashboard/styles.css"),"utf8");
  assert.ok(css.includes(".pivot-panel.fullscreen-mode #pivotCards{grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr))!important}"));
  assert.ok(app.elements.get("pivotCveTable").innerHTML.includes("CVE-PENDING"));
  assert.match(app.elements.get("pivotSummary").textContent,/excluded from active totals/);
  assert.match(app.elements.get("pivotCveTablePagination").innerHTML,/of 300 CVEs/);
  assert.equal(app.run('headerLabel("DetectedCVEs")'),"Distinct active CVEs");
});

test("machine recommendations precede CVEs and metadata and navigate to each recommendation",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToMachine({DeviceId:"machine-1",DeviceName:"example-ws11"})');
  app.query().at(-1).resolve(app.payload({
    detail:{type:"machine",id:"machine-1",record:{DeviceId:"machine-1",DeviceName:"example-ws11"}},
    cards:{pivotCards:[[2,"Related recommendations"]]},
    tables:{
      pivotCveTable:{columns:["CveId"],items:[],total:0,action:"cve"},
      pivotRecommendationTable:{columns:["RecommendationName","DetectedCVEs"],items:[{RecommendationId:"rec-0",RecommendationName:"Update browser",DetectedCVEs:20},{RecommendationId:"rec-1",RecommendationName:"Update OS",DetectedCVEs:30}],total:2,offset:0,limit:100,action:"recommendation"},
    },
  }));await tick();
  const detail=app.elements.get("pivotDetails").innerHTML;
  assert.ok(detail.indexOf('id="pivotRecommendationTable"')<detail.indexOf('id="pivotCveTable"'));
  assert.ok(detail.indexOf('id="pivotCveTable"')<detail.indexOf('class="server-record"'));
  assert.match(detail,/Related recommendations/);
  assert.match(app.elements.get("pivotCards").innerHTML,/One machine can have several recommendations/);
  const table=app.elements.get("pivotRecommendationTable");
  assert.match(table.innerHTML,/<th title="Different CVE IDs/);
  assert.match(table.innerHTML,/Update browser/);
  table.tableRows[1].click();
  assert.equal(app.query().at(-1).payload.selection.id,"rec-1");
  assert.equal(app.query().at(-1).payload.selection.type,"recommendation");
  assert.equal(app.elements.has("pivotHandoffNote"),false);
});

test("recommendation status styling is bold blue without hiding workflow controls",()=>{
  const css=fs.readFileSync(path.join(__dirname,"../dashboard/styles.css"),"utf8");
  assert.match(css,/\.tracking-status\[class\],#recommendationTrackingStatus\{color:#145b91;font-weight:800\}/);
  assert.match(html,/id="recommendationTrackingActions"/);
  assert.match(html,/id="copyRecommendationReference"/);
  assert.doesNotMatch(html,/Dashboard work status is stored against/);
});

test("search immediately hides old results, debounces and sequence-ignores superseded matches",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("overview")');
  const previous=app.query().at(-1);
  app.elements.get("findingsSearch").dispatch("input","machine-900");
  assert.equal(previous.options.signal.aborted,true);
  assert.equal(app.elements.get("findingsTable").classList.contains("query-pending"),true);
  assert.equal(app.query().length,2);
  app.elements.get("findingsSearch").dispatch("input","machine-901");
  app.flushTimers();
  assert.equal(app.query().length,3);
  assert.equal(app.query().at(-1).payload.filters.search,"machine-901");
  assert.equal(app.query().at(-1).payload.page,0);
  previous.resolve(app.payload({texts:{findingsPageStatus:"stale records"}}));await tick();
  assert.notEqual(app.elements.get("findingsPageStatus").textContent,"stale records");
  app.query().at(-1).resolve(app.payload({texts:{findingsPageStatus:"current match"}}));await tick();
  assert.equal(app.elements.get("findingsPageStatus").textContent,"current match");
  assert.equal(app.elements.get("findingsTable").classList.contains("query-pending"),false);
});

test("finding pages use server totals; search, filters and distinct-CVE mode reset pagination",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("overview")');
  const tableResult={columns:["CveId"],items:[{CveId:"CVE-2026-1"}],total:32128,offset:0,limit:100,action:"cve"};
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:tableResult}}));await tick();
  app.pageButtons[3].click();
  assert.equal(app.query().at(-1).payload.page,321);
  assert.equal(app.query().at(-1).payload.table,"findingsTable");
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{...tableResult,offset:32100}}}));await tick();
  app.elements.get("severityFilter").dispatch("change","Low");
  assert.equal(app.query().at(-1).payload.page,0);
  assert.equal(app.query().at(-1).payload.filters.severity,"Low");
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:tableResult}}));await tick();
  app.elements.get("findingsMode").value="findings";
  app.elements.get("findingsMode").dispatch("change","findings");
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:tableResult}}));await tick();
  app.run("clearDashboardResponseCache()");
  app.elements.get("findingsMode").value="cves";
  app.elements.get("findingsMode").dispatch("change","cves");
  assert.equal(app.query().at(-1).payload.mode,"cves");
  assert.equal(app.query().at(-1).payload.page,0);
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{...tableResult,total:105}}}));await tick();
  assert.match(app.elements.get("findingsPageStatus").textContent,/105 distinct CVEs/);
});

test("OS Type choices, scope chips, pagination, exports and Reset share the selected platform",async()=>{
  const app=fixture();await tick();
  assert.equal(app.query()[0].payload.filters.osType,"All");
  const facets={osTypes:["Ubuntu","Unknown","Windows11",'OS <test & "name">']};
  app.query()[0].resolve(app.payload({facets}));await tick();
  const select=app.elements.get("osTypeFilter");
  assert.match(select.innerHTML,/All operating systems/);
  assert.match(select.innerHTML,/Windows11/);
  assert.match(select.innerHTML,/OS &lt;test &amp; &quot;name&quot;&gt;/);
  app.run('activateView("overview")');
  const table={columns:["OSPlatform"],items:[{OSPlatform:"Windows11"}],total:250,offset:0,limit:100};
  app.query().at(-1).resolve(app.payload({facets,tables:{findingsTable:table}}));await tick();
  app.pageButtons[3].click();
  assert.equal(app.query().at(-1).payload.page,2);
  app.query().at(-1).resolve(app.payload({facets,tables:{findingsTable:{...table,offset:200}}}));await tick();
  select.value="Windows11";select.dispatch("change","Windows11");
  assert.equal(app.query().at(-1).payload.page,0);
  assert.equal(app.query().at(-1).payload.filters.osType,"Windows11");
  assert.match(app.elements.get("activeFilterChips").innerHTML,/<b>OS Type<\/b>Windows11/);
  app.query().at(-1).resolve(app.payload({facets,tables:{findingsTable:{...table,total:1}}}));await tick();
  assert.equal(select.value,"Windows11");
  app.elements.get("exportFindingsCsv").click();
  assert.equal(app.query().at(-1).payload.filters.osType,"Windows11");
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{...table,total:1}}}));await tick();
  const form=app.elements.get("body").children.filter(child=>child.tagName==="form").at(-1);
  assert.equal(JSON.parse(form.children[0].value).filters.osType,"Windows11");
  app.elements.get("resetFilters").click();await tick();
  assert.equal(app.run("dashboardRequest().filters.osType"),"All");
  assert.equal(select.value,"All");
  assert.match(app.elements.get("findingsPageStatus").textContent,/250/);
  assert.doesNotMatch(app.elements.get("activeFilterChips").innerHTML,/<b>OS Type<\/b>/);
});

test("first-seen and remediation shortcuts serialize the preserved filtering semantics",async()=>{
  const app=fixture();await tick();
  app.selectors["[data-new-view]"].find(button=>button.dataset.findingsMode==="cves").click();
  assert.equal(app.query().at(-1).payload.filters.newPeriodFilter,true);
  assert.equal(app.query().at(-1).payload.mode,"cves");
  app.selectors["[data-fixed-view]"].find(button=>button.dataset.findingsMode==="cves").click();
  const payload=app.query().at(-1).payload;
  assert.equal(payload.filters.remediationPeriodFilter,true);
  assert.equal(payload.filters.newPeriodFilter,false);
  assert.equal(payload.filters.exposureStatus,"All");
  assert.equal(payload.mode,"cves");
});

test("snapshot conflicts expose an explicit reload affordance and never silently acquire another run",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({detail:"expired"},409);await tick();
  assert.equal(app.elements.get("dashboardQueryStatus").hidden,false);
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/New snapshot available/);
  assert.equal(app.elements.get("reloadDashboardSnapshot").hidden,false);
  assert.equal(app.run("dashboardVisualProgress.timer"),null);
  app.run('activateView("priority")');
  assert.equal(app.run("dashboardVisualProgress.timer"),null);
  assert.equal(app.query().length,1);
  assert.equal(app.requests.filter(request=>request.url==="/api/dashboard/snapshot").length,1);
  app.elements.get("reloadDashboardSnapshot").click();
  assert.equal(app.context.reloaded,true);
});

test("network and validation failures are visible, retryable and do not reveal stale tables",async()=>{
  const app=fixture();await tick();
  app.query()[0].reject(new Error("network offline"));await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/network offline/);
  assert.equal(app.elements.get("loadingNotice").hidden,true);
  assert.equal(app.run("dashboardVisualProgress.timer"),null);
  assert.equal(app.elements.get("retryDashboardQuery").hidden,false);
  app.elements.get("retryDashboardQuery").click();
  app.query().at(-1).resolve({detail:"Invalid date range"},422);await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/Invalid date range/);
});

test("snapshot metadata failures are visible and retry metadata without requesting datasets",async()=>{
  const app=fixture({snapshotStatus:503});await tick();
  assert.equal(app.query().length,0);
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/Snapshot unavailable/);
  assert.equal(app.run("dashboardVisualProgress.timer"),null);
  app.elements.get("retryDashboardQuery").click();await tick();
  assert.equal(app.requests.filter(request=>request.url==="/api/dashboard/snapshot").length,2);
});

test("detail preparation displays the actual server stage",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToMachine({DeviceId:"machine-1",DeviceName:"example-ws11"})');
  app.query().at(-1).resolve({
    snapshotId,status:"preparing",retryAfterSeconds:2,
    progress:{stage:"query:detail:detail-workloads",elapsedSeconds:12},
  },202);await tick();
  assert.match(app.elements.get("pivotSummary").textContent,/affected workloads/);
  assert.match(app.elements.get("pivotSummary").textContent,/12s elapsed/);
});

test("detail failures are visible inside the panel and clear its busy state",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToMachine({DeviceId:"machine-1",DeviceName:"example-ws11"})');
  app.query().at(-1).reject(new Error("network offline"));await tick();
  assert.match(app.elements.get("pivotSummary").textContent,/network offline/);
  assert.equal(app.elements.get("pivotPanel")["aria-busy"],"false");
});

test("detail queries pin selection and closing detail ignores an in-flight response",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToCve({CveId:"CVE-2026-99"})');
  const detail=app.query().at(-1);
  assert.equal(detail.payload.view,"detail");
  assert.deepEqual(detail.payload.selection,{type:"cve",id:"CVE-2026-99"});
  assert.equal(detail.payload.snapshotId,snapshotId);
  app.run("clearSelectedWorkItem()");
  assert.equal(detail.options.signal.aborted,true);
  detail.resolve(app.payload({texts:{pivotTitle:"stale detail"}}));await tick();
  assert.notEqual(app.elements.get("pivotTitle").textContent,"stale detail");
  assert.equal(app.elements.get("pivotPanel").hidden,true);
});

test("successful queries without notices hide the status bar and Retry",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  assert.equal(app.elements.get("dashboardQueryStatus").hidden,true);
  assert.equal(app.elements.get("retryDashboardQuery").hidden,true);
});

test("snapshot warnings stay visible without Retry and oversized pages expose a retryable error",async()=>{
  const app=fixture({notices:["SLA policy unavailable"]});await tick();
  app.query()[0].resolve(app.payload());await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/SLA policy unavailable/);
  assert.equal(app.elements.get("retryDashboardQuery").hidden,true);
  app.run('activateView("overview")');
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{columns:[],items:Array(201).fill({}),total:201}}}));await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/oversized table page/);
  assert.equal(app.elements.get("retryDashboardQuery").hidden,false);
});

test("every workspace view queries lazily and generic tables receive bounded First/Previous/Next/Last controls",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  for(const view of ["workstations","recommendations","sla","trend","executiveSnapshot","help"]){
    app.run(`activateView("${view}")`);
    assert.equal(app.query().at(-1).payload.view,view);
    app.query().at(-1).resolve(app.payload());await tick();
  }
  app.run('clearDashboardResponseCache();activateView("workstations")');
  const table={columns:["DeviceName"],items:[{DeviceId:"machine-1",DeviceName:"Machine 1"}],total:150,offset:0,limit:100,action:"machine"};
  app.query().at(-1).resolve(app.payload({tables:{workstationTable:table}}));await tick();
  const pager=app.elements.get("workstationTablePagination");
  assert.equal(pager.pageButtons.length,4);
  assert.equal(pager.pageButtons[0].disabled,true);
  assert.equal(pager.pageButtons[3].disabled,false);
  pager.pageButtons[2].click();
  assert.equal(app.query().at(-1).payload.table,"workstationTable");
  assert.equal(app.query().at(-1).payload.page,1);
});

test("detail responses render only bounded records and independently page related entities",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToRecommendation({RecommendationId:"rec-1",DataOrigin:"Live"})');
  app.query().at(-1).resolve(app.payload({
    detail:{type:"recommendation",id:"rec-1",record:{RecommendationId:"rec-1",RecommendationName:"Upgrade product",DataOrigin:"Live"}},
    texts:{pivotTitle:"Upgrade product"},
    tables:{pivotTable:{columns:["DeviceName"],items:[],total:250,offset:0,limit:100,action:"machine"}}
  }));await tick();
  assert.equal(app.elements.get("pivotTitle").textContent,"Upgrade product");
  assert.equal(app.elements.get("defenderRemediationLink").hidden,false);
  app.elements.get("pivotTablePagination").pageButtons[3].click();
  const payload=app.query().at(-1).payload;
  assert.equal(payload.view,"detail");
  assert.equal(payload.table,"pivotTable");
  assert.equal(payload.page,2);
  assert.deepEqual(payload.selection,{type:"recommendation",id:"rec-1"});
});

test("CSV export preflights the snapshot then streams all matches with native POST, never buffering a blob",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.elements.get("exportFindingsCsv").click();
  const validation=app.query().at(-1);
  assert.equal(validation.payload.view,"overview");
  assert.equal(validation.payload.table,"findingsTable");
  validation.resolve(app.payload({tables:{findingsTable:{items:[],total:250}}}));await tick();
  const form=app.elements.get("body").children.find(child=>child.tagName==="form");
  assert.equal(form.submitted,true);
  assert.equal(form.action,"/api/dashboard/export");
  assert.equal(form.method,"POST");
  const payload=JSON.parse(form.children[0].value);
  assert.equal(payload.snapshotId,snapshotId);
  assert.equal(payload.table,"findingsTable");
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/all matching rows, not just this page/);
  const exportSource=source.split("async function exportDashboardCsv(")[1].split("// Keep the existing controls")[0];
  assert.ok(!exportSource.includes(".blob("));
});

test("recommendation tracking remains enabled after grouped related rows and uses snapshot-pinned writes",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('state.recommendationTrackingEnabled=true;pivotToRecommendation({RecommendationId:"rec-1",DataOrigin:"Live"})');
  app.query().at(-1).resolve(app.payload({
    detail:{type:"recommendation",id:"rec-1",record:{RecommendationId:"rec-1",RecommendationName:"Upgrade product",DataOrigin:"Live"}},
    tables:{pivotRecommendationTable:{columns:["RecommendationName"],items:[{RecommendationId:"rec-1",RecommendationName:"Upgrade product",OpenFindings:250}],total:1,offset:0,limit:100,action:"recommendation"}}
  }));await tick();
  assert.equal(app.elements.get("recommendationTrackingActions").hidden,false);
  app.run('void updateRecommendationTracking("InProgress")');
  const write=app.requests.at(-1);
  assert.equal(write.url,`/api/recommendation-tracking?snapshotId=${snapshotId}`);
  assert.equal(write.options.method,"PUT");
  assert.equal(write.payload.recommendationId,"rec-1");
  write.resolve({});
  await tick();
  const read=app.requests.at(-1);
  assert.equal(read.url,`/api/recommendation-tracking?snapshotId=${snapshotId}`);
  read.resolve({items:[{recommendationId:"rec-1",effectiveStatus:"InProgress"}]});
  await tick();
  assert.equal(app.query().at(-1).payload.view,"detail");
});

for(const closeControl of ["clearPivot","pivotBackdrop"]){
  test(`saved work status refreshes the originating list when closing with ${closeControl}`,async()=>{
    const app=fixture();await tick();
    app.query()[0].resolve(app.payload());await tick();
    app.run('state.recommendationTrackingEnabled=true;activateView("recommendations")');
    const row={RecommendationId:"rec-1",RecommendationName:"Upgrade product",DataOrigin:"Live",TrackingStatus:"Untracked"};
    const list=()=>app.payload({tables:{recommendationTable:{columns:["RecommendationName"],items:[row],total:1,offset:0,limit:100,action:"recommendation"}}});
    app.query().at(-1).resolve(list());await tick();
    app.run('pivotToRecommendation({RecommendationId:"rec-1",RecommendationName:"Upgrade product",DataOrigin:"Live"})');
    const detail=()=>app.payload({detail:{type:"recommendation",id:"rec-1",record:row}});
    app.query().at(-1).resolve(detail());await tick();
    app.run('void updateRecommendationTracking("InProgress")');
    app.requests.at(-1).resolve({});await tick();
    app.requests.at(-1).resolve({items:[{recommendationId:"rec-1",effectiveStatus:"InProgress"}]});await tick();
    assert.match(app.elements.get("recommendationTrackingStatus").textContent,/In progress/);
    app.query().at(-1).resolve(detail());await tick();
    const before=app.query().length;
    app.elements.get(closeControl).dispatch("click");
    assert.equal(app.query().length,before+1);
    assert.equal(app.query().at(-1).payload.view,"recommendations");
    row.TrackingStatus="InProgress";
    app.query().at(-1).resolve(list());await tick();
    assert.match(app.elements.get("recommendationTable").innerHTML,/In progress/);
    assert.equal(app.elements.get("pivotPanel").hidden,true);
  });
}

test("contextual help explains progress, SLA assessment and separate workflow status",async()=>{
  const app=fixture();await tick();
  for(const label of ["Still open","Improved","Fully resolved","Progress status","SLA risk status","Not yet due","Overdue","Deadline unknown","Cleared on time","Cleared late","Summary","Dashboard work status","In progress"]){
    assert.ok(app.run(`metricHelp(${JSON.stringify(label)})`).length>50,label);
  }
  assert.match(app.run('metricHelp("Improved")'),/still unresolved/);
  assert.match(app.run('metricHelp("Still open")'),/reporting period/);
  assert.match(app.run('metricHelp("In progress")'),/does not.*(?:Defender|SLA)/);
  assert.match(app.run('metricHelp("Confirmed on-time %")'),/known deadlines/);
  app.run('openMetricHelp("Improved")');
  assert.equal(app.elements.get("metricHelpDialog").open,true);
  assert.equal(app.elements.get("metricHelpTitle").textContent,"Improved");
  assert.match(app.elements.get("metricHelpText").textContent,/still unresolved/);
  app.elements.get("closeMetricHelp").dispatch("click");
  assert.equal(app.elements.get("metricHelpDialog").open,false);
  assert.equal(app.run('explainedCell("PendingEvidence","No",{})'),"No");
});

test("saving an unchanged work status clears the saving message without reloading analytics",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('state.recommendationTrackingEnabled=true;pivotToRecommendation({RecommendationId:"rec-1",DataOrigin:"Live"})');
  app.query().at(-1).resolve(app.payload({detail:{type:"recommendation",id:"rec-1",record:{RecommendationId:"rec-1",DataOrigin:"Live"}}}));await tick();
  app.run('state.recommendationTracking.set("rec-1",{recommendationId:"rec-1",effectiveStatus:"InProgress"})');
  const count=app.query().length,saving=app.run('updateRecommendationTracking("InProgress")');
  app.requests.at(-1).resolve({});await tick();
  app.requests.at(-1).resolve({items:[{recommendationId:"rec-1",effectiveStatus:"InProgress"}]});
  assert.equal(await saving,true);
  assert.match(app.elements.get("recommendationTrackingStatus").textContent,/In progress/);
  assert.doesNotMatch(app.elements.get("recommendationTrackingStatus").textContent,/Saving/);
  assert.equal(app.query().length,count);
});

test("help is available on status cells, SLA columns, cards and Summary without changing row actions",async()=>{
  const app=fixture();await tick();
  app.run(`cards("pivotCards",[[3,"Machines with open risk"],[2,"CVEs improved"],[1,"Recommendations fully resolved"]]);
    table("recommendationTable",["ProgressStatus","SlaStatus"],[{ProgressStatus:"Improved",SlaStatus:"Overdue"}],()=>{window.rowOpened=true;});
    ensureManagementReport("executive");
    renderDashboardChart("executiveManagementSlaSnapshot",{kind:"entity-sla-status",rows:[]});`);
  assert.equal((app.elements.get("pivotCards").innerHTML.match(/data-help-key=/g)||[]).length,3);
  const markup=app.elements.get("recommendationTable").innerHTML;
  for(const key of ["Progress Status","SLA risk status","Improved","Overdue"])assert.ok(markup.includes(`data-help-key="${key}"`),key);
  assert.match(app.elements.get("executiveManagement").innerHTML,/data-help-key="Summary"/);
  for(const label of ["Not yet due","Overdue","Deadline unknown","Fully cleared","Cleared on time","Cleared late"]){
    assert.ok(app.elements.get("executiveManagementSlaSnapshot").innerHTML.includes(`data-help-key="${label}"`),label);
  }
  const row=app.elements.get("recommendationTable").tableRows[0],target={closest:()=>({dataset:{helpKey:"Improved"}})};
  row.listeners.click[0]({target});
  row.listeners.keydown[0]({target,key:"Enter",preventDefault(){}});
  assert.equal(app.context.window.rowOpened,undefined);
  row.click();
  assert.equal(app.context.window.rowOpened,true);
});

for(const failRefresh of [false,true]){
  test(`work status ${failRefresh?"refresh":"write"} failures remain explicit and retryable`,async()=>{
    const app=fixture();await tick();
    app.query()[0].resolve(app.payload());await tick();
    app.run('state.recommendationTrackingEnabled=true;pivotToRecommendation({RecommendationId:"rec-1",DataOrigin:"Live"})');
    app.query().at(-1).resolve(app.payload({detail:{type:"recommendation",id:"rec-1",record:{RecommendationId:"rec-1",DataOrigin:"Live"}}}));await tick();
    const saving=app.run('updateRecommendationTracking("InProgress")');
    app.requests.at(-1).resolve({},failRefresh?200:503);await tick();
    if(failRefresh)app.requests.at(-1).resolve({},503);
    assert.equal(await saving,false);
    assert.match(app.elements.get("recommendationTrackingStatus").textContent,failRefresh?/was saved, but refreshing it failed/:/update failed/);
    assert.equal(app.run('state.recommendationTracking.has("rec-1")'),false);
    if(failRefresh){
      app.elements.get("retryDashboardQuery").dispatch("click");
      const read=app.requests.at(-1);
      assert.equal(read.options.method,undefined);
      assert.ok(read.url.startsWith("/api/recommendation-tracking?"));
      read.resolve({items:[{recommendationId:"rec-1",effectiveStatus:"InProgress"}]});await tick();
      assert.match(app.elements.get("recommendationTrackingStatus").textContent,/In progress/);
    }
  });
}

test("new filter scopes clear prior table contents even if a report response contains only a validation context",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("overview")');
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{columns:["CveId"],items:[{CveId:"OLD-CVE"}],total:1,offset:0,limit:100,action:"none"}}}));await tick();
  assert.match(app.elements.get("findingsTable").innerHTML,/OLD-CVE/);
  app.elements.get("severityFilter").dispatch("change","Low");
  assert.equal(app.elements.get("findingsTable").innerHTML,"");
  app.query().at(-1).resolve(app.payload({texts:{findingsListContext:"No history in the selected period"}}));await tick();
  assert.ok(!app.elements.get("findingsTable").innerHTML.includes("OLD-CVE"));
});

test("executive CSV exports the selected detail representation, never just four severity summary rows",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.elements.get("exportExecutiveSnapshotCsv").click();
  assert.equal(app.query().at(-1).payload.view,"executiveSnapshot");
  assert.equal(app.query().at(-1).payload.table,"executiveSnapshotManagementMachineTable");
  app.run('state.executiveSnapshotUnit="cves"');
  app.elements.get("exportExecutiveSnapshotCsv").click();
  assert.equal(app.query().at(-1).payload.table,"executiveSnapshotManagementCveTable");
  app.run('state.executiveSnapshotUnit="recommendations"');
  app.elements.get("exportExecutiveSnapshotCsv").click();
  assert.equal(app.query().at(-1).payload.table,"executiveSnapshotManagementRecommendationTable");
});

test("management reports use entity views and have no hidden finding-instance sections",async()=>{
  const app=fixture();await tick();
  assert.equal(app.query()[0].payload.filters.managementReporting,true);
  assert.equal(app.query()[0].payload.filters.includeFindingEvidence,false);
  assert.equal(app.run("findingsList.mode"),"cves");
  assert.equal(app.run("state.reportingEntity"),"machines");
  const current={machines:{Open:5},cves:{Open:3},recommendations:{Open:2}};
  app.query()[0].resolve(app.payload({
    metadata:{management:{version:1,periods:[current]}},
    cards:{executiveManagementCards:[[5,"Machines with open risk"],[3,"Open vulnerabilities (unique CVEs)"]]},
  }));await tick();
  assert.match(app.elements.get("filterCount").textContent,/5 machines with open risk · 3 unique open CVEs · 2 open recommendations/);
  assert.match(app.elements.get("executiveManagementCards").innerHTML,/Machines with open risk/);
  assert.match(app.elements.get("executiveManagement").innerHTML,/500 machines is one vulnerability/);
  assert.match(app.elements.get("executiveManagement").innerHTML,/pending verification remains open/);
  assert.equal(app.query().at(-1).payload.filters.includeFindingEvidence,false);
  for(const id of ["executiveTechnicalEvidence","executiveSnapshotTechnicalEvidence","slaTechnicalEvidence","trendTechnicalEvidence","trendWorkflowEvidence"]){
    assert.equal(app.elements.has(id),false);
  }
});

test("management entity tables keep ten-row pagination and their own CSV contract",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("executiveSnapshot")');await tick();
  const id="executiveSnapshotManagementMachineTable";
  app.query().at(-1).resolve(app.payload({tables:{[id]:{
    columns:["DeviceName","ProgressStatus"],items:[{DeviceId:"machine-1",DeviceName:"Endpoint",ProgressStatus:"Improved"}],
    total:42,offset:0,limit:10,action:"machine",
  }}}));await tick();
  const pager=app.elements.get(id+"Pagination");
  pager.pageButtons[2].click();
  const request=app.query().at(-1).payload;
  assert.equal(request.table,id);
  assert.equal(request.page,1);
  assert.equal(request.limit,10);
  assert.equal(request.filters.managementReporting,true);
});

test("recommendation rows show machines and CVEs without exposing supporting record totals",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("recommendations")');
  app.query().at(-1).resolve(app.payload({tables:{recommendationTable:{
    columns:["RecommendationName","AffectedMachines","DetectedCVEs"],
    items:[{RecommendationId:"rec-1",RecommendationName:"Update software",AffectedMachines:500,DetectedCVEs:1,OpenFindings:1000000}],
    total:1,offset:0,limit:100,action:"recommendation",
  }}}));await tick();
  const markup=app.elements.get("recommendationTable").innerHTML;
  assert.match(markup,/Update software/);
  assert.match(markup,/Distinct active CVEs/);
  assert.match(markup,/<td(?: [^>]*)?>500<\/td>/);
  assert.ok(!markup.includes("1000000")&&!markup.includes("1,000,000"));
});

test("Summary contains machine and CVE severity totals plus only a compact SLA status dashboard",async()=>{
  const app=fixture();await tick();
  const period=slaDashboardReport().periods[0];
  Object.assign(period.cves,{openWithin:10,openOverdue:2,totalOpen:13});
  app.query()[0].resolve(app.payload({
    metadata:{management:{sla:{unit:"distinct-entities",entityPeriods:[period],coverageGap:false}}},
    charts:{
      executiveManagementSeverity:{kind:"entity-severity",rows:[{label:"Critical",machines:3,cves:5},{label:"High",machines:2,cves:4},{label:"Medium",machines:1,cves:3},{label:"Low",machines:0,cves:2},{label:"Unknown",machines:0,cves:0}]},
      executiveManagementSlaSnapshot:{kind:"entity-sla-status",rows:[{label:"CVEs",...period.cves},{label:"Machines",...period.machines}]},
    },
  }));await tick();
  const root=app.elements.get("executiveManagement");
  assert.ok(root.innerHTML.indexOf('id="executiveManagementSeverity"')<root.innerHTML.indexOf('id="executiveManagementSlaSnapshot"'));
  const severity=app.elements.get("executiveManagementSeverity").innerHTML;
  assert.ok(severity.indexOf('data-severity-entity="machines"')<severity.indexOf('data-severity-entity="cves"'));
  assert.match(severity,/Machines \/ workload instances by severity/);
  assert.match(severity,/Unique CVEs by severity/);
  assert.match(severity,/Critical<\/span><strong>3<\/strong>/);
  assert.match(severity,/Critical<\/span><strong>5<\/strong>/);
  assert.ok(!severity.includes("Unknown"));
  for(const suffix of ["SlaStatus","SlaPolicy","SlaSeverity","Movement","Progress","ComparisonTable","MachineTable","CveTable","RecommendationTable"]){
    assert.ok(!root.innerHTML.includes(`id="executiveManagement${suffix}"`),suffix);
  }
  const status=app.elements.get("executiveManagementSlaSnapshot").innerHTML;
  assert.match(status,/Distinct CVEs and machines, counted separately/);
  assert.match(status,/<th scope="row">CVEs<\/th><td>13<\/td><td>10<\/td><td>2<\/td><td>1<\/td>/);
  assert.match(status,/<th scope="row">Machines<\/th>/);
  assert.match(status,/Fully cleared/);
  assert.doesNotMatch(status,/machine\/CVE outcomes|Open within SLA %|Confirmed on-time %/);
  assert.ok(!app.query()[0].payload.filters.includeFindingEvidence);
});

for(const view of ["slaDashboard","executiveSnapshot"]){
  test(`${view} shows separate CVE and machine severity snapshots and preserves drill-down scope`,async()=>{
    const app=fixture();await tick();
    app.query()[0].resolve(app.payload());await tick();
    const report=slaDashboardReport(),period=report.periods[0],base=period.cves.severity[0];
    period.cves.severity=["Critical","High","Medium","Low","Unknown"].map((label,index)=>({...base,label,totalOpen:[5,4,0,2,1][index]}));
    period.machines.severity=["Critical","High","Medium","Low"].map((label,index)=>({...base,label,totalOpen:[3,2,1,0][index]}));
    app.run(`state.osType="Linux";state.team="Ops";state.executiveSnapshotOwner="Ops";activateView("${view}")`);
    const metadata=view==="slaDashboard"
      ?{slaDashboard:report}
      :{management:{sla:{entityPeriods:report.periods,periods:[{Period:"Selected period"}]}}};
    app.query().at(-1).resolve(app.payload({metadata}));await tick();
    const root=app.elements.get(view==="slaDashboard"?"slaDashboardVisuals":"executiveSnapshotManagementLeadershipSnapshot");
    const markup=root.innerHTML;
    assert.ok(markup.indexOf('aria-label="Unresolved severity snapshot"')<markup.indexOf('aria-label="Leadership SLA snapshot"'));
    for(const [label,cves,machines] of [["Critical",5,3],["High",4,2],["Medium",0,1],["Low",2,0],["Unknown",1,0]]){
      const card=markup.slice(markup.indexOf(`data-vulnerability-severity="${label}"`)).split("</button>")[0];
      assert.match(card,new RegExp(`<strong>${cves}</strong><span>Distinct unresolved CVEs</span>`));
      assert.match(card,new RegExp(`<strong>${machines}</strong><span>Affected machines</span>`));
    }
    assert.match(markup,/Fully cleared means confirmation is complete/);
    root.filterButtons.find(button=>button.dataset.vulnerabilitySeverity==="Critical").click();await tick();
    const query=app.query().at(-1).payload;
    assert.equal(query.view,"overview");
    assert.equal(query.mode,"cves");
    assert.equal(query.filters.severity,"Critical");
    assert.equal(query.filters.osType,"Linux");
    assert.equal(query.filters.team,"Ops");
  });
}

test("severity snapshots distinguish missing counts from zero and hide unused Unknown severity",async()=>{
  const app=fixture();await tick();
  const period=slaDashboardReport().periods[0];
  period.cves.severity.push({...period.cves.severity[0],label:"High",totalOpen:0});
  const markup=app.run(`unresolvedSeveritySnapshot(${JSON.stringify(period)})`);
  assert.doesNotMatch(markup,/data-vulnerability-severity="Unknown"/);
  const high=markup.slice(markup.indexOf('data-vulnerability-severity="High"')).split("</button>")[0];
  assert.match(high,/<strong>0<\/strong><span>Distinct unresolved CVEs<\/span>/);
  assert.match(high,/<strong>Waiting for data<\/strong><span>Affected machines<\/span>/);
  for(const label of ["Medium","Low"]){
    const card=markup.slice(markup.indexOf(`data-vulnerability-severity="${label}"`)).split("</button>")[0];
    assert.equal((card.match(/Waiting for data/g)||[]).length,2);
  }
});

test("Executive Snapshot retains detailed completion analysis and period comparisons",async()=>{
  const app=fixture();await tick();
  const period=slaDashboardReport().periods[0];
  Object.assign(period.cves,{completionPercent:75,confirmedFixes:5,completedWithin:3,completedLate:1,completedUnknown:1});
  app.context.period=period;
  app.run(`ensureManagementReport("executiveSnapshot");renderManagementSla("executiveSnapshot",{entityPeriods:[period]});renderDashboardChart("executiveSnapshotManagementSlaSeverity",{kind:"entity-sla-status",rows:[{label:"CVEs",...period.cves},{label:"Machines",...period.machines}]})`);
  const markup=app.elements.get("executiveSnapshotManagement").innerHTML;
  for(const suffix of ["SlaSnapshot","SlaStatus","SlaSeverity","Movement","Progress","ComparisonTable"])assert.ok(markup.includes(`id="executiveSnapshotManagement${suffix}"`));
  const graph=app.elements.get("executiveSnapshotManagementSlaSeverity").innerHTML;
  assert.match(graph,/Distinct CVEs and machines, counted separately/);
  assert.match(graph,/Fully cleared/);
  assert.match(app.elements.get("executiveSnapshotManagementSlaStatus").innerHTML,/75.0% of assessed fully cleared CVEs were on time/);
  assert.doesNotMatch(graph,/finding|machine\/CVE/i);
});

test("SLA displays show distinct entity counts, full clearances, and retained policy parameters",async()=>{
  const app=fixture();await tick();
  const period=slaDashboardReport().periods[0];
  Object.assign(period.cves,{totalOpen:6,openWithin:3,openOverdue:2,unknownOpen:1,completionPercent:75,confirmedFixes:4,completedWithin:3,completedLate:1});
  app.context.entitySla={entityPeriods:[period]};
  app.run(`state.slaPolicy={policies:[{severity:"Critical",slaDays:2},{severity:"Critical",slaDays:4,knownExploitRequired:true},{severity:"High",slaDays:7}]};
    ensureManagementReport("executiveSnapshot");
    renderManagementSla("executiveSnapshot",entitySla);
    renderDashboardChart("executiveSnapshotManagementSlaSnapshot",{kind:"entity-sla-status",rows:[{label:"CVEs",...entitySla.entityPeriods[0].cves}]});`);
  const status=app.elements.get("executiveSnapshotManagementSlaStatus").innerHTML;
  assert.match(status,/6 distinct unresolved CVEs/);
  assert.match(status,/75.0% of assessed fully cleared CVEs were on time/);
  const table=app.elements.get("executiveSnapshotManagementSlaSnapshot").innerHTML;
  assert.match(table,/Distinct CVEs and machines, counted separately/);
  assert.match(table,/Fully cleared/);
  assert.doesNotMatch(table,/machine\/CVE|outcomes/);
  assert.match(app.elements.get("executiveSnapshotManagementSlaPolicy").textContent,/Critical \+ known exploit: 4 days/);
  assert.match(app.elements.get("executiveSnapshotManagementPolicyRules").textContent,/first observation on the machine/);
  assert.match(app.elements.get("executiveSnapshotManagementPolicyRules").textContent,/on or before the deadline/);
  assert.equal(app.run('slaDashboardPercent(null)'),"Waiting for data");
  app.run('state.slaPolicy=null;renderManagementSla("executiveSnapshot",entitySla)');
  assert.match(app.elements.get("executiveSnapshotManagementSlaPolicy").textContent,/policy is unavailable/);
});

test("Reporting severity links open distinct vulnerabilities and preserve workspace filters",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("trend");state.osType="Linux";state.search="openssl";state.subscription="sub-a";state.team="Ops";ensureManagementReport("trend");renderDashboardChart("trendManagementSeverity",{kind:"entity-severity",rows:[{label:"Critical",machines:1,cves:2}]});');
  app.elements.get("trendManagementSeverity").filterButtons[0].click();await tick();
  app.flushTimers();await tick();
  const request=app.query().at(-1).payload;
  assert.equal(request.view,"overview");
  assert.equal(request.mode,"cves");
  assert.equal(request.filters.severity,"Critical");
  assert.equal(request.filters.osType,"Linux");
  assert.equal(request.filters.search,"openssl");
  assert.equal(request.filters.subscription,"sub-a");
  assert.equal(request.filters.team,"Ops");
});

test("Executive severity links carry the report subscription and owner to vulnerabilities",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("executiveSnapshot");state.executiveSnapshotSubscription="report-sub";state.executiveSnapshotOwner="Report team";openSeverityVulnerabilities("High");');
  const request=app.query().at(-1).payload;
  assert.equal(request.filters.subscription,"report-sub");
  assert.equal(request.filters.team,"Report team");
  assert.equal(request.filters.severity,"High");
});

test("persistent quick filters and removable chips refresh the selected item without closing it",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  const quick=html.slice(html.indexOf('class="quick-filters"'),html.indexOf('id="activeFilterChips"'));
  assert.match(quick,/id="searchFilter"/);
  assert.match(quick,/id="severityFilter"/);
  assert.equal((html.match(/id="severityFilter"/g)||[]).length,1);
  assert.equal((html.match(/id="searchFilter"/g)||[]).length,1);
  app.run('state.selectedEntity={type:"machine",id:"machine-x"};state.pivotSourceLabel="executiveSnapshot";state.osType="Linux";');
  app.elements.get("severityFilter").dispatch("change","Critical");await tick();
  assert.equal(app.run("state.selectedEntity.id"),"machine-x");
  assert.equal(app.query().at(-1).payload.view,"detail");
  assert.equal(app.query().at(-1).payload.filters.severity,"Critical");
  assert.equal(app.query().at(-1).payload.filters.managementSourceView,"executiveSnapshot");
  assert.match(app.elements.get("activeFilterChips").innerHTML,/Remove Severity filter: Critical/);
  const chip=app.elements.get("activeFilterChips").filterButtons.find(button=>button.dataset.removeFilter==="Severity");
  chip.click();await tick();
  assert.equal(app.run("state.severity"),"All");
  assert.equal(app.run("state.osType"),"Linux");
  assert.equal(app.run("state.selectedEntity.id"),"machine-x");
  assert.equal(app.elements.get("severityFilter").value,"All");
  app.run('removeWorkspaceFilter("Type");removeWorkspaceFilter("Domains");');
  assert.equal(app.run("state.recommendationTypes.size"),2);
  assert.equal(app.run("state.domains.size"),5);
  assert.doesNotMatch(app.elements.get("activeFilterChips").innerHTML,/data-remove-filter="(?:Type|Domains)"/);
});

test("SLA no-outcome states remain ungraded and coverage gaps stay explicit without colors",async()=>{
  const app=fixture();await tick();
  app.context.entitySla={entityPeriods:[slaDashboardReport().periods[0]]};
  app.run(`ensureManagementReport("sla");renderManagementSla("sla",entitySla)`);
  assert.match(app.elements.get("slaManagementSlaStatus").innerHTML,/No fully cleared CVEs to assess/);
  assert.ok(!app.elements.get("slaManagementSlaStatus").innerHTML.includes("100.0%"));
  app.run(`entitySla.coverageGap=true;renderManagementSla("sla",entitySla)`);
  assert.match(app.elements.get("slaManagementSlaStatus").innerHTML,/Coverage gap/);
});

test("provisional fixes are visible without inventing a completed SLA rate",async()=>{
  const app=fixture();await tick();
  const period=slaDashboardReport().periods[0];
  period.cves.awaitingConfirmation=5;
  app.context.entitySla={entityPeriods:[period]};
  app.run(`ensureManagementReport("executiveSnapshot");
    renderManagementSla("executiveSnapshot",entitySla);
    renderDashboardChart("executiveSnapshotManagementSlaSeverity",{kind:"entity-sla-status",rows:[{label:"CVEs",...entitySla.entityPeriods[0].cves}]});`);
  const status=app.elements.get("executiveSnapshotManagementSlaStatus").innerHTML;
  assert.match(status,/No fully cleared CVEs to assess/);
  assert.match(status,/5 with fixes awaiting confirmation/);
  assert.ok(!status.includes("100.0%"));
  const graph=app.elements.get("executiveSnapshotManagementSlaSeverity").innerHTML;
  assert.match(graph,/Distinct CVEs and machines/);
  assert.match(graph,/Fully cleared/);
  assert.ok(!graph.includes('style="width:'));
  const report=app.elements.get("executiveSnapshotManagement").innerHTML;
  assert.match(report,/id="executiveSnapshotManagementFixActivity"/);
  assert.match(report,/first qualified absence/);
  assert.match(report,/returned detection revokes/);
  assert.match(report,/excluded from completed SLA outcomes/);
});

test("browser requests server entity SLA results without a local finding aggregation",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("slaDashboard")');await tick();
  assert.equal(app.query().at(-1).payload.view,"slaDashboard");
  assert.equal(app.query().at(-1).payload.filters.includeFindingEvidence,false);
  assert.equal(app.run("typeof slaSeverityRows"),"undefined");
  assert.equal(app.run("typeof renderLegacyDashboard"),"undefined");
});

test("historical severity is unavailable rather than zero before retained observations",async()=>{
  const app=fixture();await tick();
  app.run(`ensureManagementReport("executive");renderDashboardChart("executiveManagementSeverity",{kind:"entity-severity",available:false,rows:[]})`);
  assert.match(app.elements.get("executiveManagementSeverity").innerHTML,/unavailable, not zero/);
});

test("catalog options and legacy Prioritize navigation use the single Recommendations page",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("recommendations")');await tick();
  app.elements.get("recommendationCatalogStatus").dispatch("change","No current exposure");await tick();
  app.elements.get("recommendationCatalogSort").dispatch("change","cves");await tick();
  assert.equal(app.query().at(-1).payload.filters.recommendationCatalogStatus,"No current exposure");
  assert.equal(app.query().at(-1).payload.filters.recommendationCatalogSort,"cves");
  app.elements.get("recommendationWorkspaceFilters").click();
  assert.equal(app.elements.get("filterBar").hidden,false);
  app.elements.get("resetRecommendationCatalog").click();await tick();
  assert.equal(app.run("state.recommendationCatalogStatus"),"All");
  assert.equal(app.run("state.recommendationCatalogSort"),"name");
  app.run('activateView("priority")');await tick();
  assert.equal(app.query().at(-1).payload.view,"recommendations");
  assert.equal(app.query().at(-1).payload.filters.recommendationCatalogSort,"priority");
  assert.equal(app.run("state.activeView"),"recommendations");
  assert.ok(!html.includes('data-view="priority"'));
});

test("machine detail retains the reporting scope that opened it",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("executiveSnapshot")');await tick();
  app.run('pivotToMachine({DeviceId:"machine-x"})');await tick();
  assert.equal(app.query().at(-1).payload.filters.managementSourceView,"executiveSnapshot");
  assert.equal(app.query().at(-1).payload.filters.includeFindingEvidence,false);
});

test("CVE buttons inside finding-instance rows open CVE detail rather than the surrounding finding",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("overview")');
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{columns:["CveId"],items:[{FindingKey:"finding-1",CveId:"CVE-2026-999"}],total:1,offset:0,limit:100,action:"finding"}}}));await tick();
  app.elements.get("findingsTable").cveButtons[0].click();
  assert.deepEqual(app.query().at(-1).payload.selection,{type:"cve",id:"CVE-2026-999"});
});

test("busy native exports retry with their original payload and neutral progress",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.elements.get("exportFindingsCsv").click();
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{items:[],total:250}}}));await tick();
  const body=app.elements.get("body"),frame=body.children.find(child=>child.tagName==="iframe");
  const original=body.children.filter(child=>child.tagName==="form").at(-1).children[0].value;
  app.run('state.severity="Low"');
  frame.contentDocument={body:{textContent:JSON.stringify({status:"preparing",detail:"Waiting for a report",retryAfterSeconds:2})}};
  frame.dispatch("load");
  assert.equal(app.elements.get("dashboardQueryStatus").role,"status");
  assert.equal(app.elements.get("retryDashboardQuery").hidden,true);
  app.flushTimers();await tick();
  const forms=body.children.filter(child=>child.tagName==="form");
  assert.equal(forms.length,2);
  assert.equal(forms.at(-1).children[0].value,original);
});

test("native CSV error documents remain visible for unavailable and expired snapshots",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.elements.get("exportFindingsCsv").click();
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{items:[],total:250}}}));await tick();
  const frame=app.elements.get("body").children.find(child=>child.tagName==="iframe");
  frame.contentDocument={body:{textContent:JSON.stringify({detail:"Dashboard snapshot is unavailable"})}};
  frame.dispatch("load");
  assert.equal(app.elements.get("dashboardQueryStatus").hidden,false);
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/snapshot is unavailable/);
  assert.equal(app.elements.get("reloadDashboardSnapshot").hidden,true);
  frame.contentDocument.body.textContent=JSON.stringify({detail:"This snapshot expired. Reload the dashboard to select the current snapshot."});
  frame.dispatch("load");
  assert.equal(app.elements.get("reloadDashboardSnapshot").hidden,false);
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/New snapshot available/);
});

test("missing export tables and empty scopes show explicit notices without submitting an empty download",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.elements.get("exportFindingsCsv").click();
  app.query().at(-1).resolve(app.payload());await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/export detail is unavailable/);
  assert.ok(!app.elements.get("body").children.some(child=>child.tagName==="form"));
  app.elements.get("exportFindingsCsv").click();
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{items:[],total:0}}}));await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/No matching rows to export/);
});

test("preparing queries poll the identical payload and request ID until the exact result is ready",async()=>{
  const app=fixture();await tick();
  const initial=app.query()[0];
  assert.equal(initial.payload.asyncQuery,true);
  assert.ok(initial.payload.requestId);
  for(let index=0;index<12;index++){
    app.query().at(-1).resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
    assert.match(app.elements.get("loadingNotice").innerHTML,/Preparing exact snapshot results/);
    assert.equal(app.elements.get("loadingNotice").hidden,false);
    app.flushTimers();await tick();
    assert.equal(app.query().at(-1).options.body,initial.options.body);
  }
  assert.equal(app.query().length,13);
  app.query().at(-1).resolve(app.payload({texts:{newActivityContext:"Exact completed result"}}));await tick();
  assert.equal(app.elements.get("newActivityContext").textContent,"Exact completed result");
  assert.equal(app.elements.get("loadingNotice").hidden,true);
  assert.equal(app.elements.get("dashboardQueryStatus").hidden,true);
});

test("a preparation failure is visible and retry starts a new logical request",async()=>{
  const app=fixture();await tick();
  const firstId=app.query()[0].payload.requestId;
  app.query()[0].resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  app.flushTimers();await tick();
  app.query().at(-1).resolve({detail:"Snapshot preparation failed; retry later."},503);await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/preparation failed/);
  assert.equal(app.elements.get("loadingNotice").hidden,true);
  assert.equal(app.run("dashboardVisualProgress.timer"),null);
  assert.equal(app.elements.get("retryDashboardQuery").hidden,false);
  app.elements.get("retryDashboardQuery").click();
  assert.notEqual(app.query().at(-1).payload.requestId,firstId);
});

test("changing views aborts a preparing query and cancels its pending poll timer",async()=>{
  const app=fixture();await tick();
  const summary=app.query()[0];
  summary.resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  app.run('activateView("overview")');await tick();
  const overview=app.query().at(-1);
  assert.equal(summary.options.signal.aborted,true);
  const cancellation=app.requests.find(request=>request.url==="/api/dashboard/query/cancel");
  assert.equal(cancellation.payload.requestId,summary.payload.requestId);
  assert.equal(cancellation.options.keepalive,true);
  assert.notEqual(overview.payload.requestId,summary.payload.requestId);
  app.flushTimers();await tick();
  assert.equal(app.query().length,2);
  overview.resolve(app.payload());await tick();
  assert.equal(app.elements.get("loadingNotice").hidden,true);
});

test("late poll responses cannot overwrite a newer filter scope",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  app.flushTimers();await tick();
  const stalePoll=app.query().at(-1);
  app.elements.get("severityFilter").dispatch("change","Low");
  const current=app.query().at(-1);
  assert.equal(stalePoll.options.signal.aborted,true);
  assert.notEqual(current.payload.requestId,stalePoll.payload.requestId);
  current.resolve(app.payload({texts:{newActivityContext:"Low severity scope"}}));await tick();
  stalePoll.resolve(app.payload({texts:{newActivityContext:"Stale all-severity scope"}}));await tick();
  assert.equal(app.elements.get("newActivityContext").textContent,"Low severity scope");
  assert.equal(app.elements.get("dashboardQueryStatus").hidden,true);
});

test("closing preparing detail cancels polling without an unhandled rejection",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToCve({CveId:"CVE-2026-88"})');
  const detail=app.query().at(-1);
  detail.resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  assert.match(app.elements.get("pivotSummary").textContent,/Preparing exact snapshot detail/);
  app.run("clearSelectedWorkItem()");await tick();
  assert.equal(detail.options.signal.aborted,true);
  app.flushTimers();await tick();
  assert.equal(app.query().length,2);
  assert.equal(app.elements.get("pivotPanel").hidden,true);
});

test("export validation can prepare asynchronously while the final native form keeps the original export payload",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.elements.get("exportFindingsCsv").click();
  const validation=app.query().at(-1);
  validation.resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/Preparing exact export detail/);
  assert.equal(app.elements.get("retryDashboardQuery").hidden,true);
  app.flushTimers();await tick();
  assert.equal(app.query().at(-1).options.body,validation.options.body);
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{items:[],total:250}}}));await tick();
  const form=app.elements.get("body").children.find(child=>child.tagName==="form");
  const exportRequest=JSON.parse(form.children[0].value);
  assert.equal(exportRequest.snapshotId,snapshotId);
  assert.equal(exportRequest.table,"findingsTable");
  assert.equal(exportRequest.asyncQuery,undefined);
  assert.equal(exportRequest.requestId,undefined);
  assert.equal(form.submitted,true);
});

test("a snapshot conflict during preparation stops polling and retains the explicit reload affordance",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({snapshotId,status:"preparing",retryAfterSeconds:2},202);await tick();
  app.flushTimers();await tick();
  app.query().at(-1).resolve({detail:"This snapshot expired."},409);await tick();
  assert.equal(app.elements.get("reloadDashboardSnapshot").hidden,false);
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/New snapshot available/);
  app.flushTimers();await tick();
  assert.equal(app.query().length,2);
});

function slaDashboardReport(){
  const entity=()=>({
    openWithin:1,openOverdue:1,unknownOpen:1,totalOpen:3,openWithinPercent:50,
    completedWithin:0,completedLate:0,completedUnknown:0,completionPercent:null,
    confirmedFixes:0,awaitingConfirmation:1,observedFixes:1,improved:0,
    severity:[{label:"Critical",totalOpen:3,openWithin:1,openOverdue:1,unknownOpen:1,completionPercent:null,confirmedFixes:0,completedWithin:0,completedLate:0,completedUnknown:0,awaitingConfirmation:1,improved:0}],
  });
  const period=(label,start,end)=>({
    label,start,end,coverage:"complete",cves:entity(),machines:entity(),
  });
  const periods=[
    period("Month to date","2026-10-01","2026-10-24"),
    period("Last completed week","2026-10-12","2026-10-18"),
    period("Previous completed week","2026-10-05","2026-10-11"),
    period("Last completed month","2026-09-01","2026-09-30"),
    period("Previous completed month","2026-08-01","2026-08-31"),
  ];
  return {unit:"distinct-entities",asOfUtc:"2026-10-24T12:00:00Z",history:{startUtc:"2026-08-01T00:00:00Z",snapshots:85},periods,coverageGap:false};
}

function compliancePeriods(){
  const current=slaDashboardReport().periods[0];
  return ["Week to date","Month to date","Rolling 90 days","Year to date","Custom dates"].map(label=>({
    ...current,label,
    cves:{...current.cves,openWithin:3,openOverdue:1,openWithinPercent:75,completedWithin:2,completedLate:1,completedUnknown:2,completionPercent:200/3},
    machines:{...current.machines,openWithin:1,openOverdue:1,openWithinPercent:50,completedWithin:1,completedLate:1,completionPercent:50},
  }));
}

for(const view of ["slaDashboard","executiveSnapshot"]){
  test(`${view} shows all compliance periods, both percentages and distinct denominators`,async()=>{
    const app=fixture();await tick();
    app.run(`activateView("${view}")`);await tick();
    const report={...slaDashboardReport(),compliancePeriods:compliancePeriods()};
    const metadata=view==="slaDashboard"?{slaDashboard:report}:{management:{sla:{entityPeriods:report.periods,compliancePeriods:report.compliancePeriods}}};
    app.query().at(-1).resolve(app.payload({metadata}));await tick();
    const markup=app.elements.get(`${view}ComplianceCards`).innerHTML;
    for(const period of report.compliancePeriods)assert.ok(markup.includes(`<h3>${period.label}</h3>`));
    assert.match(markup,/Distinct CVEs/);
    assert.match(markup,/Distinct machines/);
    assert.match(markup,/Unresolved within SLA %/);
    assert.match(markup,/Confirmed on-time clearance %/);
    assert.match(markup,/75\.0%/);
    assert.match(markup,/66\.7%/);
    assert.match(markup,/50\.0%/);
    assert.match(markup,/3 \/ 4 known-deadline unresolved/);
    assert.match(markup,/2 \/ 3 known-deadline full clearances/);
    assert.match(markup,/1 \/ 2 known-deadline unresolved/);
    assert.match(markup,/2 deadline unknown \(excluded\)/);
    assert.match(markup,/1 awaiting confirmation; still unresolved, not a clearance/);
    assert.doesNotMatch(markup,/NaN|undefined/);
  });

  test(`${view} custom compliance dates are validated, cached and isolated from other reporting ranges`,async()=>{
    const app=fixture();await tick();
    app.run(`activateView("${view}")`);await tick();
    app.query().at(-1).resolve(app.payload());await tick();
    assert.equal(app.elements.get(`${view}ComplianceEnd`).max,"2026-10-24");
    const before=app.query().length;
    app.elements.get(`${view}ComplianceStart`).value="2026-10-25";
    app.elements.get(`${view}ComplianceEnd`).value="2026-10-24";
    app.elements.get(`${view}ComplianceApply`).click();await tick();
    assert.equal(app.query().length,before);
    assert.match(app.elements.get(`${view}ComplianceMessage`).textContent,/Choose valid/);
    app.elements.get(`${view}ComplianceStart`).value="2026-10-01";
    app.elements.get(`${view}ComplianceEnd`).value="2026-10-25";
    app.elements.get(`${view}ComplianceApply`).click();await tick();
    assert.equal(app.query().length,before);
    app.elements.get(`${view}ComplianceEnd`).value="2026-10-24";
    app.elements.get(`${view}ComplianceApply`).click();await tick();
    const selected=app.query().at(-1).payload;
    assert.equal(selected.filters.slaComplianceStart,"2026-10-01");
    assert.equal(selected.filters.slaComplianceEnd,"2026-10-24");
    assert.equal(selected.filters.executiveSnapshotPeriod,"30days");
    assert.equal(selected.filters.statisticsPeriod,"week");
    assert.equal(app.elements.get(`${view}ComplianceMessage`).textContent,"");
    const key=app.run(`dashboardResponseKey(dashboardRequest("${view}"))`);
    app.run('state.slaCompliance.end="2026-10-23"');
    assert.notEqual(app.run(`dashboardResponseKey(dashboardRequest("${view}"))`),key);
    assert.equal(app.run('"slaComplianceStart" in dashboardRequest("overview").filters'),false);
    app.run('state.slaCompliance.end="2026-10-24"');
    app.query().at(-1).resolve(app.payload());await tick();
    app.elements.get(`${view}ComplianceClear`).click();await tick();
    assert.equal(app.run(`"slaComplianceStart" in dashboardRequest("${view}").filters`),false);
    assert.equal(app.run('state.slaCompliance.start'),"");
    assert.equal(app.elements.get(`${view}ComplianceStart`).value,"");
  });
}

test("compliance percentages distinguish real zero, empty denominator and insufficient history",async()=>{
  const app=fixture();await tick();
  const periods=compliancePeriods();
  periods[0].cves={...periods[0].cves,openWithin:0,openOverdue:2,openWithinPercent:0};
  periods[0].machines={...periods[0].machines,completedWithin:0,completedLate:0,completionPercent:null};
  periods[1].coverage="partial";
  app.context.periods=periods;
  app.run('renderComplianceSnapshots("slaDashboard",periods)');
  const markup=app.elements.get("slaDashboardComplianceCards").innerHTML;
  assert.match(markup,/>0\.0%</);
  assert.match(markup,/0 \/ 2 known-deadline unresolved/);
  assert.match(markup,/0 \/ 0 known-deadline full clearances; none to assess/);
  assert.match(markup,/Waiting for data/);
  const partial=markup.split("<h3>Month to date</h3>")[1].split("<h3>Rolling 90 days</h3>")[0];
  assert.match(partial,/Insufficient retained history/);
  assert.doesNotMatch(partial,/\d+\.\d%|0 \/ 0|NaN|undefined/);
  assert.match(html,/not a period average/);
});

test("dedicated graphical SLA navigation leaves the Remediate work lists separate",async()=>{
  const app=fixture();await tick();
  app.run('state.slaPolicy={policies:[{severity:"Critical",knownExploitRequired:false,slaDays:2},{severity:"Critical",knownExploitRequired:true,slaDays:4}]}');
  app.run('activateView("slaDashboard")');await tick();
  assert.equal(app.query().at(-1).payload.view,"slaDashboard");
  app.query().at(-1).resolve(app.payload({metadata:{slaDashboard:slaDashboardReport()}}));await tick();
  const markup=app.elements.get("slaDashboardVisuals").innerHTML;
  assert.match(markup,/Distinct unresolved CVEs/);
  assert.match(markup,/3 CVEs/);
  assert.match(markup,/3 machines/);
  assert.match(markup,/1 not yet due/);
  assert.match(markup,/1 overdue/);
  assert.match(markup,/1 deadline unknown/);
  assert.match(markup,/CVEs fully cleared this month/);
  assert.match(markup,/No fully cleared CVEs to assess/);
  assert.doesNotMatch(markup,/50\.0%|sla-rate-ring|NaN|undefined/);
  assert.match(markup,/with fixes awaiting confirmation/);
  assert.match(markup,/Pending fixes remain unresolved/);
  assert.match(markup,/Standard: 2 days · Known exploit: 4 days/);
  assert.doesNotMatch(markup,/<table/);
  assert.match(app.elements.get("filterCount").textContent,/3 distinct unresolved CVEs · 3 affected machines/);
  const critical=app.elements.get("slaDashboardVisuals").filterButtons[0];
  critical.click();await tick();
  assert.equal(app.query().at(-1).payload.view,"overview");
  assert.equal(app.query().at(-1).payload.filters.severity,"Critical");
  app.run('activateView("sla")');await tick();
  assert.equal(app.query().at(-1).payload.view,"sla");
});

test("SLA calendar graphics compare backlog and confirmed-fix counts in completed periods",async()=>{
  const app=fixture();await tick();
  const report=slaDashboardReport();
  report.periods[1].cves.totalOpen=13;
  report.periods[1].cves.openWithin=11;
  report.periods[3].cves.confirmedFixes=3;
  report.periods[3].cves.completedWithin=3;
  report.periods[3].cves.completionPercent=100;
  report.periods[4].cves.confirmedFixes=6;
  report.periods[4].cves.completedWithin=6;
  report.periods[4].cves.completionPercent=100;
  app.context.slaReport=report;
  app.run("renderSlaDashboard(slaReport)");
  const markup=app.elements.get("slaDashboardVisuals").innerHTML;
  assert.match(markup,/Week over week/);
  assert.match(markup,/Month over month/);
  assert.match(markup,/2026-10-12 - 2026-10-18/);
  assert.match(markup,/2026-09-01 - 2026-09-30/);
  assert.match(markup,/Change: \+10 CVEs unresolved/);
  assert.match(markup,/Change: -3 CVEs fully cleared/);
  assert.match(markup,/100\.0% of assessed fully cleared CVEs were on time/);
  assert.doesNotMatch(markup,/sla-rate-ring|NaN|undefined/);
  assert.match(markup,/Monday through Sunday in UTC/);
});

test("partial SLA history withholds rates and changes instead of fabricating success",async()=>{
  const app=fixture();await tick();
  const report=slaDashboardReport();
  report.periods[0].coverage="partial";
  report.periods[2].coverage="partial";
  report.periods[2].cves.openWithinPercent=99;
  report.periods[3].coverage="unavailable";
  app.context.slaReport=report;
  app.run("renderSlaDashboard(slaReport)");
  const markup=app.elements.get("slaDashboardVisuals").innerHTML;
  assert.match(markup,/Full-period history is unavailable/);
  assert.match(markup,/Change: Waiting for data/);
  assert.match(markup,/Month-to-date completion counts cover retained observations only/);
  assert.doesNotMatch(markup,/99\.0%|Change: -49/);
});

test("zero SLA rates remain zero and absent assessments remain unavailable",async()=>{
  const app=fixture();await tick();
  const report=slaDashboardReport();
  Object.assign(report.periods[0].cves,{openWithinPercent:0,openWithin:0,openOverdue:2,completionPercent:0,completedLate:1,confirmedFixes:1});
  app.context.slaReport=report;
  app.run("renderSlaDashboard(slaReport)");
  const markup=app.elements.get("slaDashboardVisuals").innerHTML;
  assert.match(markup,/0\.0% of assessed fully cleared CVEs were on time/);
  assert.match(markup,/2 overdue/);
  assert.doesNotMatch(markup,/sla-rate-ring/);
  assert.doesNotMatch(markup,/100\.0%/);
  assert.equal(app.run("slaDashboardPercent(null)"),"Waiting for data");
});

test("all unresolved work not yet due never looks like completed remediation",async()=>{
  const app=fixture();await tick();
  const report=slaDashboardReport();
  for(const period of report.periods){
    for(const entity of ["cves","machines"])Object.assign(period[entity],{openWithin:12,openOverdue:0,unknownOpen:0,totalOpen:12,openWithinPercent:100,awaitingConfirmation:0,observedFixes:0});
  }
  Object.assign(report.periods[0].cves.severity[0],{totalOpen:12,openWithin:12,openOverdue:0,unknownOpen:0,awaitingConfirmation:0});
  app.context.slaReport=report;
  app.run("renderSlaDashboard(slaReport)");
  const markup=app.elements.get("slaDashboardVisuals").innerHTML;
  assert.match(markup,/12 CVEs/);
  assert.match(markup,/12 not yet due/);
  assert.match(markup,/CVEs fully cleared this month/);
  assert.match(markup,/Not yet due does not mean remediated/);
  assert.match(markup,/No fully cleared CVEs to assess/);
  assert.doesNotMatch(markup,/sla-rate-ring|NaN|undefined/);
  assert.doesNotMatch(markup.replace(/<[^>]*>/g,""),/100(?:\.0)?%/);
});

test("confirmed fixes with unknown deadlines are counted but not assessed as on time",async()=>{
  const app=fixture();await tick();
  const report=slaDashboardReport();
  Object.assign(report.periods[0].cves,{confirmedFixes:2,completedUnknown:2,observedFixes:3});
  Object.assign(report.periods[0].cves.severity[0],{confirmedFixes:2,completedUnknown:2});
  app.context.slaReport=report;
  app.run("renderSlaDashboard(slaReport)");
  const markup=app.elements.get("slaDashboardVisuals").innerHTML;
  assert.match(markup,/2 CVEs fully cleared this month/);
  assert.match(markup,/2 deadline unknown/);
  assert.match(markup,/No known completion deadlines to assess/);
  assert.doesNotMatch(markup.replace(/<[^>]*>/g,""),/100(?:\.0)?%|NaN|undefined/);
});

test("SLA screen rejects old pair-count reports and never renders pair totals",async()=>{
  const app=fixture();await tick();
  const report=slaDashboardReport();
  report.periods[0].totalOpen=1900000;
  app.context.slaReport=report;
  app.run("renderSlaDashboard(slaReport)");
  assert.doesNotMatch(app.elements.get("slaDashboardVisuals").innerHTML,/1,900,000|unresolved outcomes|Open machine\/CVE outcomes/);
  report.unit="machine-cve";
  assert.throws(()=>app.run("renderSlaDashboard(slaReport)"),/response is incomplete/);
});

test("missing SLA response data surfaces a retryable error and clears stale visuals",async()=>{
  const app=fixture();await tick();
  app.elements.get("slaDashboardVisuals").innerHTML="Old SLA summary";
  app.run('activateView("slaDashboard")');await tick();
  app.query().at(-1).resolve(app.payload());await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/SLA dashboard response is incomplete/);
  assert.equal(app.elements.get("slaDashboardVisuals").innerHTML,"");
  assert.equal(app.elements.get("retryDashboardQuery").hidden,false);
});

test("leadership donuts keep remaining exposure separate from confirmed clearance and use explicit counts",async()=>{
  const app=fixture();await tick();
  const report=slaDashboardReport();
  Object.assign(report.periods[0].cves,{completedWithin:2,completedLate:1,completedUnknown:1,confirmedFixes:4,completionPercent:200/3});
  Object.assign(report.periods[0].machines,{openWithin:7,openOverdue:2,unknownOpen:1,totalOpen:10});
  app.context.slaReport=report;
  app.run("renderSlaDashboard(slaReport)");
  const markup=app.elements.get("slaDashboardVisuals").innerHTML;
  assert.equal((markup.match(/class="sla-summary-donut"/g)||[]).length,4);
  assert.match(markup,/CVEs remaining: 1 Not yet due, 1 Overdue, 1 Deadline unknown/);
  assert.match(markup,/Machines remaining: 7 Not yet due, 2 Overdue, 1 Deadline unknown/);
  assert.match(markup,/CVEs fully cleared: 2 Cleared on time, 1 Cleared late, 1 Clearance deadline unknown/);
  assert.match(markup,/66\.7% of assessed fully cleared CVEs were on time/);
  assert.match(markup,/No confirmed full clearances in this period/);
  assert.match(markup,/--sla-ring:#dce4e9/);
  assert.match(markup,/Month to date: 2026-10-01 - 2026-10-24 UTC/);
  assert.match(markup,/Backlog and period clearances are different measures/);
});

test("management summaries use the same leadership charts and colored confirmed-remediation categories",async()=>{
  const app=fixture();await tick();
  const report=slaDashboardReport();
  app.context.sla={entityPeriods:[report.periods[0]],periods:[{Period:"Latest 30 days"}]};
  app.run('ensureManagementReport("sla");renderManagementSla("sla",sla)');
  assert.match(app.elements.get("slaManagementLeadershipSnapshot").innerHTML,/SLA at a glance/);
  assert.match(app.elements.get("slaManagementLeadershipSnapshot").innerHTML,/Latest 30 days/);
  const markup=app.elements.get("slaManagementSlaStatus").innerHTML;
  for(const category of ["cleared","late","pending","improved","unknown"])assert.match(markup,new RegExp(`class="sla-outcome-${category}"`));
  assert.match(markup,/No fully cleared CVEs to assess/);
});

test("severity drill-down filters reset on leaving the pivot while manual workspace filters survive",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('state.osType="Linux";state.team="Ops";activateView("slaDashboard");openSeverityVulnerabilities("Critical")');
  assert.equal(app.query().at(-1).payload.filters.severity,"Critical");
  app.query().at(-1).resolve(app.payload());await tick();
  app.run('activateView("slaDashboard")');
  const filters=app.run("dashboardRequest().filters");
  assert.equal(filters.severity,"All");
  assert.equal(filters.osType,"Linux");
  assert.equal(filters.team,"Ops");
  assert.equal(app.elements.get("severityFilter").value,"All");
  assert.equal(filters.pivotFilterRestore,undefined);
  assert.equal(filters.pivotFilters,undefined);
  assert.equal(filters.machineHistory,undefined);
  assert.equal(filters.machineHistoryPeriod,undefined);
});

test("repeated pivots restore the original subscription, owner and severity without reviving cleared filters",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('state.severity="Medium";state.subscription="original-sub";state.team="Original";activateView("executiveSnapshot");state.executiveSnapshotSubscription="report-sub";state.executiveSnapshotOwner="Report owner";openSeverityVulnerabilities("High");openSeverityVulnerabilities("Critical");activateView("workstations")');
  assert.equal(app.run("state.severity"),"Medium");
  assert.equal(app.run("state.subscription"),"original-sub");
  assert.equal(app.run("state.team"),"Original");
  app.run('openSeverityVulnerabilities("Critical");resetFilters();activateView("slaDashboard")');
  assert.equal(app.run("state.severity"),"All");
  assert.equal(app.run("state.subscription"),"All");
});

test("activity pivots restore exposure and activity filters when navigating to another screen",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.selectors["[data-fixed-view]"].find(button=>button.dataset.findingsMode==="cves").click();
  assert.equal(app.run("state.remediationPeriodFilter"),true);
  assert.equal(app.elements.get("exposureStatusFilter").value,"All");
  app.run('activateView("workstations")');
  assert.equal(app.run("state.remediationPeriodFilter"),false);
  assert.equal(app.run("state.exposureStatus"),"DetectedAndPending");
  app.selectors["[data-new-view]"].find(button=>button.dataset.findingsMode==="cves").click();
  assert.equal(app.run("state.newPeriodFilter"),true);
  app.run('activateView("executive")');
  assert.equal(app.run("state.newPeriodFilter"),false);
  assert.equal(app.elements.get("applyNewPeriodFilter").checked,false);
});

test("machine history loads on demand with independent dated filters and an exportable history table",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToMachine({DeviceId:"machine-x"})');
  const detail={type:"machine",id:"machine-x",record:{DeviceId:"machine-x",DeviceName:"Machine X"}};
  assert.equal(app.query().at(-1).payload.filters.machineHistoryPeriod,undefined);
  app.query().at(-1).resolve(app.payload({detail}));await tick();
  assert.equal(app.elements.get("machineHistoryControls").hidden,false);
  assert.equal(app.elements.get("machineHistoryStart").value,"2026-09-25");
  assert.equal(app.elements.get("machineHistoryEnd").value,"2026-10-24");
  app.elements.get("machineHistoryPeriod").value="custom";
  app.elements.get("machineHistoryPeriod").dispatch("change","custom");
  app.elements.get("machineHistoryStart").value="2026-10-05";
  app.elements.get("machineHistoryEnd").value="2026-10-20";
  app.elements.get("applyMachineHistory").click();
  const request=app.query().at(-1).payload;
  assert.equal(request.selection.id,"machine-x");
  assert.equal(request.filters.machineHistoryPeriod,"custom");
  assert.equal(request.filters.machineHistoryStart,"2026-10-05");
  assert.equal(request.filters.machineHistoryEnd,"2026-10-20");
  app.query().at(-1).resolve(app.payload({
    detail,metadata:{machineHistory:{start:"2026-10-05",end:"2026-10-20",coverage:"lifecycle-only"}},
    tables:{pivotMachineHistoryTable:{columns:["CveId","Change","ChangeTimeUtc"],items:[{CveId:"CVE-X",Change:"Confirmed fixed",ChangeTimeUtc:"2026-10-12T00:00:00Z"}],total:1,offset:0,limit:100,action:"cve"}},
  }));await tick();
  assert.match(app.elements.get("machineHistoryContext").textContent,/2026-10-05 through 2026-10-20 UTC/);
  assert.match(app.elements.get("machineHistoryContext").textContent,/only transitions supported by retained lifecycle timestamps/);
  assert.match(app.elements.get("pivotMachineHistoryTable").innerHTML,/Confirmed fixed/);
  assert.equal(app.run('dashboardRequest("detail","pivotMachineHistoryTable").filters.machineHistoryStart'),"2026-10-05");
  app.elements.get("clearPivot").click();
  assert.equal(app.elements.get("machineHistoryControls").hidden,true);
  app.run('pivotToMachine({DeviceId:"another-machine"})');
  assert.equal(app.query().at(-1).payload.filters.machineHistoryPeriod,undefined);
});
