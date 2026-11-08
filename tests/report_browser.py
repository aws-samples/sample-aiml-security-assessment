"""Execute report handlers against the rendered table and controls."""

import json
import shutil
import subprocess

from bs4 import BeautifulSoup

DRIVER = r"""
const fs=require('fs'),vm=require('vm'),input=JSON.parse(fs.readFileSync(0,'utf8'));
const fields={},downloads={},urls=new Map(),scrolls=[],snapshots=[];
function element(description={}) {
 const e={...description,events:{},style:{display:description.display||''},dataset:description.dataset||{},
  classList:{add(){},remove(){}},textContent:description.text||'',value:description.value||'',
  addEventListener(name,fn){this.events[name]=fn;},
  hasAttribute(name){return Object.hasOwn(this.attrs||{},name);},
  getAttribute(name){return (this.attrs||{})[name]||null;},
  setAttribute(){},removeAttribute(){},
  scrollIntoView(){scrolls.push(this.id);},
  querySelector(selector){
   if(selector==='.theme-label')return element();
   if(selector==='td:nth-child(3) code')return {textContent:this.checkId};
   if(selector==='.col-domain')return {textContent:this.finding};
   throw Error('Unexpected element query: '+selector);
  }};
 return e;
}
for(const [id,description] of Object.entries(input.fields))fields[id]=element({...description,id});
const rows=input.rows.map(element),buttons=input.buttons.map(element),headers=input.headers.map(element);
const tbody={children:[...rows],querySelectorAll(selector){if(selector!=='tr')throw Error(selector);return this.children;},
 appendChild(row){this.children=this.children.filter(r=>r!==row);this.children.push(row);}};
global.document={
 documentElement:element(),
 getElementById(id){return fields[id]||null;},
 querySelector(selector){if(selector==='#findingsTable tbody')return tbody;
  if(selector.startsWith('#'))return fields[selector.slice(1)]||null;throw Error(selector);},
 querySelectorAll(selector){
  if(selector==='#findingsTable tbody tr')return tbody.children;
  if(selector==='[data-filter-service]')return buttons;
  if(selector==='#findingsTable th.sortable')return headers;
  if(selector==='.nav-item'||selector==='.section')return [];
  throw Error('Unexpected document query: '+selector);
 },
 createElement(tag){if(tag!=='a')throw Error(tag);
  return {click(){downloads[this.download]=urls.get(this.href);}};}
};
global.localStorage={getItem(){return null;},setItem(){}};
global.window={addEventListener(){},pageYOffset:0};
global.Blob=class {constructor(parts){this.content=parts.join('');}};
global.URL={createObjectURL(blob){const id='blob:'+urls.size;urls.set(id,blob.content);return id;},
 revokeObjectURL(){}};
global.setTimeout=()=>{};
function snapshot(){
 return {visible:tbody.children.filter(r=>r.style.display!=='none').map(r=>r.index),
  values:Object.fromEntries(Object.entries(fields).map(([id,e])=>[id,e.value])),
  scrolls:[...scrolls]};
}
for(const script of input.scripts)vm.runInThisContext(script);
snapshots.push(snapshot());
for(const action of input.actions){
 let target,event;
 if(action.type==='filter-button'){
  target=buttons.find(b=>b.dataset.filterService===action.service&&b.dataset.filterStatus===action.status);
  event='click';
 }else if(action.type==='sort'){
  target=headers.find(h=>h.dataset.sort===action.column);event='click';
 }else{
  target=fields[action.id];event=action.type==='change'?'change':action.type==='input'?'input':'click';
  if(action.type==='change'||action.type==='input'){
   if(!target)throw Error('Missing rendered control: '+action.id);
   if(target.options&&!target.options.includes(action.value))throw Error('Option absent: '+action.id+'='+action.value);
   target.value=action.value;
  }
 }
 if(!target||!target.events[event])throw Error('Missing rendered handler: '+JSON.stringify(action));
 target.events[event].call(target);
 snapshots.push(snapshot());
}
console.log(JSON.stringify({snapshots,downloads}));
"""


def _description(element):
    return {
        "text": element.get_text(" ", strip=True),
        "attrs": dict(element.attrs),
        "dataset": {
            "".join(
                part.title() if index else part
                for index, part in enumerate(key[5:].split("-"))
            ): value
            for key, value in element.attrs.items()
            if key.startswith("data-")
        },
    }


def exercise_report(html, actions):
    soup = BeautifulSoup(html, "html.parser")
    fields = {}
    for element in soup.select("[id]"):
        field = _description(element)
        if element.name == "select":
            selected = element.select_one("option[selected]") or element.select_one(
                "option"
            )
            field["value"] = selected.get("value", "") if selected else ""
            field["options"] = [
                option.get("value", "") for option in element.select("option")
            ]
        else:
            field["value"] = element.get("value", "")
        fields[element["id"]] = field
    fields["aisf-data"]["text"] = soup.select_one("#aisf-data").string
    rows = []
    for index, row in enumerate(soup.select("#findingsTable tbody tr[data-service]")):
        rows.append(
            {
                **_description(row),
                "index": index,
                "display": "none" if "display: none" in row.get("style", "") else "",
                "checkId": row.select_one("td:nth-child(3) code").get_text(),
                "finding": row.select_one(".col-domain").get_text(),
            }
        )
    scripts = [
        script.string
        for script in soup.find_all("script")
        if script.string
        and (
            "function applyFilters()" in script.string
            or ("aisf-json" in script.string and "createObjectURL" in script.string)
        )
    ]
    assert len(scripts) == 2, "Both shipped table and export handlers must execute."
    node = shutil.which("node")
    assert node, "Node is required to execute the report's actual handlers."
    process = subprocess.run(
        [node, "-e", DRIVER],
        input=json.dumps(
            {
                "scripts": scripts,
                "fields": fields,
                "rows": rows,
                "buttons": [
                    _description(button)
                    for button in soup.select("[data-filter-service]")
                ],
                "headers": [
                    _description(header)
                    for header in soup.select("#findingsTable th.sortable")
                ],
                "actions": actions,
            }
        ),
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
    )
    result = json.loads(process.stdout)
    result["rows"] = rows
    return result
