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

function fixture({snapshotStatus=200, notices=[]}={}) {
  const elements = new Map(), nodes = [], requests = [], timers = new Map();
  let timerId = 0;
  function node(id="") {
    const classes = new Set();
    const value = {
      id, dataset:{}, value:"", textContent:"", innerHTML:"", hidden:false, disabled:false,
      listeners:{}, options:[], children:[], style:{setProperty(){},removeProperty(){}},
      classList:{add:(...names)=>names.forEach(name=>classes.add(name)),remove:(...names)=>names.forEach(name=>classes.delete(name)),contains:name=>classes.has(name),toggle(name,force){const next=force??!classes.has(name);if(next)classes.add(name);else classes.delete(name);return next;}},
      addEventListener(event,handler){(this.listeners[event]??=[]).push(handler);},
      dispatch(event,value){for(const handler of this.listeners[event]||[])handler({target:{value,checked:value},preventDefault(){},stopPropagation(){}});},
      setAttribute(key,value){this[key]=value;},removeAttribute(key){delete this[key];},
      querySelectorAll(selector){
        if(selector.includes("table,"))return nodes.filter(item=>item.id.endsWith("Table")||item.id.endsWith("Cards"));
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
      insertAdjacentHTML(_,markup){for(const [,id] of markup.matchAll(/\bid="([^"]+)"/g))node(id);},
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
  const views = ["executive","overview","workstations","recommendations","priority","sla","trend","executiveSnapshot","help"];
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
    document,console,AbortController,Set,Map,Date,Number,URL:{createObjectURL:()=>"blob:test",revokeObjectURL(){}},
    window:{VULNERABILITY_VIEW_CONFIG:{},addEventListener(){},scrollTo(){},innerHeight:900},
    history:{},location:{pathname:"/",search:"",hash:"",reload(){context.reloaded=true;},assign(){}},
    localStorage:{getItem:()=>null,setItem(){}},matchMedia:()=>({matches:false}),
    navigator:{clipboard:{writeText:async()=>{}}},requestAnimationFrame:callback=>callback(),
    setTimeout(callback){const id=++timerId;timers.set(id,callback);return id;},clearTimeout:id=>timers.delete(id),
    fetch(url,options={}){
      const request={url,options,payload:options.body?JSON.parse(options.body):null};
      requests.push(request);
      if(url==="/api/dashboard/snapshot")return Promise.resolve(response({...snapshot,notices},snapshotStatus));
      if(url==="/api/health")return Promise.resolve(response({}));
      if(url==="/api/auth")return Promise.resolve(response({enabled:false}));
      if(url.startsWith("/api/branding/logo"))return Promise.resolve(response({},404));
      return new Promise((resolve,reject)=>{request.resolve=(payload,status=200)=>resolve(response(payload,status));request.reject=reject;});
    },
  });
  vm.runInContext(source,context);
  return {
    context,elements,requests,selectors,pageButtons,response,
    run:code=>vm.runInContext(code,context),
    query:()=>requests.filter(request=>request.url==="/api/dashboard/query"),
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
  assert.equal(app.elements.get("newFindingCount").textContent,"15");
  assert.equal(app.elements.get("newCveCount").textContent,"5");
  assert.equal(app.elements.get("loadingNotice").hidden,true);
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
  app.query()[0].resolve(app.payload({texts:{executiveDeltaContext:"prepared summary"}}));await tick();
  app.run('activateView("overview")');
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{columns:["CveId"],items:[{CveId:"CVE-CACHED"}],total:1,offset:0,limit:100,action:"cve"}}}));await tick();
  const count=app.query().length;
  app.run('activateView("executive")');
  assert.equal(app.query().length,count);
  assert.equal(app.elements.get("executiveDeltaContext").textContent,"prepared summary");
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

test("machine detail distinguishes active CVEs from pending evidence and labels row counts as evidence",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('pivotToMachine({DeviceId:"machine-1",DeviceName:"example-ws11"})');
  app.query().at(-1).resolve(app.payload({
    detail:{type:"machine",id:"machine-1",record:{DeviceId:"machine-1",DeviceName:"example-ws11"}},
    cards:{pivotCards:[[165,"Distinct active CVEs"],[185,"Active finding instances"],[150,"Pending findings"]]},
    texts:{pivotSummary:"165 distinct active CVEs · 185 active finding instances · 150 pending evidence rows, excluded from active totals."},
    tables:{pivotFindingTable:{columns:["FindingStatus","CveId"],items:[{FindingStatus:"PendingVerification",CveId:"CVE-PENDING"}],total:335,offset:0,limit:100,action:"finding",rowLabel:"evidence rows"}},
  }));await tick();
  assert.ok(app.elements.get("pivotCards").innerHTML.includes("Distinct active CVEs"));
  assert.ok(app.elements.get("pivotCards").innerHTML.includes("Pending findings"));
  assert.ok(app.elements.get("pivotFindingTable").innerHTML.includes("CVE-PENDING"));
  assert.match(app.elements.get("pivotSummary").textContent,/excluded from active totals/);
  assert.match(app.elements.get("pivotFindingTablePagination").innerHTML,/of 335 evidence rows/);
  assert.equal(app.run('headerLabel("DetectedCVEs")'),"Distinct active CVEs");
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
  app.elements.get("findingsMode").value="cves";
  app.elements.get("findingsMode").dispatch("change","cves");
  assert.equal(app.query().at(-1).payload.mode,"cves");
  assert.equal(app.query().at(-1).payload.page,0);
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{...tableResult,total:105}}}));await tick();
  assert.match(app.elements.get("findingsPageStatus").textContent,/105 distinct CVEs/);
});

test("first-seen and remediation shortcuts serialize the preserved filtering semantics",async()=>{
  const app=fixture();await tick();
  app.selectors["[data-new-view]"].find(button=>button.dataset.findingsMode==="cves").click();
  assert.equal(app.query().at(-1).payload.filters.newPeriodFilter,true);
  assert.equal(app.query().at(-1).payload.mode,"cves");
  app.selectors["[data-fixed-view]"].find(button=>button.dataset.findingsMode==="findings").click();
  const payload=app.query().at(-1).payload;
  assert.equal(payload.filters.remediationPeriodFilter,true);
  assert.equal(payload.filters.newPeriodFilter,false);
  assert.equal(payload.filters.exposureStatus,"All");
  assert.equal(payload.mode,"findings");
});

test("snapshot conflicts expose an explicit reload affordance and never silently acquire another run",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve({detail:"expired"},409);await tick();
  assert.equal(app.elements.get("dashboardQueryStatus").hidden,false);
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/New snapshot available/);
  assert.equal(app.elements.get("reloadDashboardSnapshot").hidden,false);
  app.run('activateView("priority")');
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
  assert.equal(app.elements.get("retryDashboardQuery").hidden,false);
  app.elements.get("retryDashboardQuery").click();
  app.query().at(-1).resolve({detail:"Invalid date range"},422);await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/Invalid date range/);
});

test("snapshot metadata failures are visible and retry metadata without requesting datasets",async()=>{
  const app=fixture({snapshotStatus:503});await tick();
  assert.equal(app.query().length,0);
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/Snapshot unavailable/);
  app.elements.get("retryDashboardQuery").click();await tick();
  assert.equal(app.requests.filter(request=>request.url==="/api/dashboard/snapshot").length,2);
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

test("snapshot notices stay visible and oversized pages fail rather than entering the browser UI",async()=>{
  const app=fixture({notices:["SLA policy unavailable"]});await tick();
  app.query()[0].resolve(app.payload());await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/SLA policy unavailable/);
  app.run('activateView("overview")');
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{columns:[],items:Array(201).fill({}),total:201}}}));await tick();
  assert.match(app.elements.get("dashboardQueryMessage").textContent,/oversized table page/);
});

test("every workspace view queries lazily and generic tables receive bounded First/Previous/Next/Last controls",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  for(const view of ["workstations","recommendations","priority","sla","trend","executiveSnapshot","help"]){
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
  assert.equal(app.query().at(-1).payload.table,"executiveSnapshotFindingTable");
  app.run('state.executiveSnapshotUnit="recommendations"');
  app.elements.get("exportExecutiveSnapshotCsv").click();
  assert.equal(app.query().at(-1).payload.table,"executiveSnapshotRecommendationTable");
});

test("CVE buttons inside finding-instance rows open CVE detail rather than the surrounding finding",async()=>{
  const app=fixture();await tick();
  app.query()[0].resolve(app.payload());await tick();
  app.run('activateView("overview")');
  app.query().at(-1).resolve(app.payload({tables:{findingsTable:{columns:["CveId"],items:[{FindingKey:"finding-1",CveId:"CVE-2026-999"}],total:1,offset:0,limit:100,action:"finding"}}}));await tick();
  app.elements.get("findingsTable").cveButtons[0].click();
  assert.deepEqual(app.query().at(-1).payload.selection,{type:"cve",id:"CVE-2026-999"});
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
  app.query().at(-1).resolve(app.payload({texts:{executiveDeltaContext:"Exact completed result"}}));await tick();
  assert.equal(app.elements.get("executiveDeltaContext").textContent,"Exact completed result");
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
  current.resolve(app.payload({texts:{executiveDeltaContext:"Low severity scope"}}));await tick();
  stalePoll.resolve(app.payload({texts:{executiveDeltaContext:"Stale all-severity scope"}}));await tick();
  assert.equal(app.elements.get("executiveDeltaContext").textContent,"Low severity scope");
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
