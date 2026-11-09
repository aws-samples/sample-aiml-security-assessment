"""AISF context and exports alongside the shared assessment findings table."""

import html
import json


def text(value: object) -> str:
    return html.escape(str(value), quote=True)


def field(label: str, value: object) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return f"<dt>{text(label)}</dt><dd>{text(value)}</dd>"


def render_context(register: dict) -> str:
    summary = register["summary"]
    preset_notice = ""
    if register["scope"].get("enable_aisf", False):
        labels = {
            "bedrock": "Amazon Bedrock",
            "sagemaker": "Amazon SageMaker",
            "agentcore": "Amazon Bedrock AgentCore",
            "agent-registry": "Agent Registry",
            "responsible-ai-grc": "Responsible AI GRC",
            "owasp": "OWASP",
        }
        enabled_sources = [
            labels[source]
            for source, selected in register["scope"]["source_selection"].items()
            if selected
        ]
        missing_sources = [
            label
            for source, label in labels.items()
            if not register["scope"]["source_selection"].get(source, False)
        ]
        preset_status = (
            "AISF assessment preset requested; effective scope is incomplete."
            if missing_sources
            else "AISF assessment preset enabled."
        )
        preset_notice = (
            '<p class="finding-details"><strong>'
            + preset_status
            + "</strong> Effective collectors: "
            + text(", ".join(enabled_sources) or "none")
            + ". "
        )
        if missing_sources:
            preset_notice += (
                "Missing collectors: "
                + text(", ".join(missing_sources))
                + ". Check the deployed preset and rerun the missing assessments. "
            )
        preset_notice += (
            "Optional artifact object reads retain their independent settings.</p>"
        )
    result = [
        '<div id="aisf-context">',
        '<p class="finding-details">'
        + text(summary["check_results"])
        + " observations across "
        + text(summary["distinct_source_checks"])
        + " distinct source checks. Includes "
        + text(summary["source_advisories"])
        + " source advisories and "
        + text(summary["unavailable_results"])
        + " unavailable observations; "
        + text(summary["gap_count"])
        + " coverage gaps. Passed describes a source observation, not whole AISF control compliance. "
        "N/A includes source advice, manual review and unavailable evidence; original statuses are retained.</p>",
        preset_notice,
        '<div class="assessment-actions">'
        '<button type="button" class="btn btn-reset" id="aisf-json">Export all AISF JSON</button>'
        '<button type="button" class="btn btn-reset" id="aisf-csv">Export all AISF CSV</button></div>'
        '<p class="finding-details">Exports contain every accepted check observation and all coverage gaps, regardless of filters.</p>',
    ]
    if register["gaps"]:
        result.append(
            '<details class="finding-more"><summary>Coverage gaps and incomplete inputs ('
            + text(len(register["gaps"]))
            + ')</summary><div class="finding-more-body"><dl>'
        )
        for gap in register["gaps"]:
            result.append(
                field(
                    gap["kind"], {key: val for key, val in gap.items() if key != "kind"}
                )
            )
        result.append("</dl></div></details>")
    if not register["checks"]:
        result.append(
            '<p class="finding-details">No accepted check observations are available. Review the scope and input gaps above; absent evidence is not a Passed or N/A result.</p>'
        )
    result.append(
        '<details class="finding-more"><summary>Assessment scope and mapping provenance</summary>'
        '<div class="finding-more-body"><p>Equivalent Agentic AI lens and OWASP category aliases share their native '
        "source observation. Source advisories and unavailable evidence are identified separately from automated check results. "
        "Global evidence does not fill regional gaps.</p><dl>"
        + field("Automated check results", summary["source_results"])
        + field("Scope", register["scope"])
        + field("Mapping source revision", register["source_revision"])
        + field("Catalog SHA-256", register["catalog_sha256"])
        + field("Mapping SHA-256", register["mapping_sha256"])
        + "</dl></div></details></div>"
    )
    payload = (
        json.dumps(register, sort_keys=True, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    result.append(f'<script type="application/json" id="aisf-data">{payload}</script>')
    return "".join(result)


def render_check_details(check: dict) -> str:
    result = [
        '<div class="aisf-source-context"><strong>AI workload check context</strong><dl>'
        + field("Resource ID", check["resource"])
        + field("Source owner", check["source_owner"])
        + field("Execution ID", check["execution_id"])
        + field("Result kind", check["result_kind"])
        + field("Evidence kind", check["evidence_kind"])
        + field("Reviewed source predicate", check["predicate"])
        + field("Source limitations", check["limitations"])
        + "</dl>"
    ]
    if check["result_kind"] == "source-advisory":
        result.append(
            "<p><strong>Source advisory.</strong> Existing collector advice or a manual-evidence limitation; "
            "the original status is retained. This is not an automated check result.</p>"
        )
    elif check["result_kind"] == "unavailable":
        result.append(
            "<p><strong>Evidence unavailable.</strong> The source could not complete the inspection. "
            "Its original status is retained and the coverage gap remains open.</p>"
        )
    if check["aisf_links"]:
        result.append("<strong>Reviewed AISF predicate mappings</strong>")
        for mapping in check["aisf_links"]:
            result.append(
                "<dl>"
                + field("AISF control", mapping["control_id"])
                + field("Question", mapping["question"])
                + field("Predicate coverage", mapping["coverage"])
                + field("Covered predicates", mapping["covered_predicates"])
                + field("Mapping limitations", mapping["limitations"])
                + "</dl>"
            )
        result.append(
            "<p>Predicate mappings provide context; a Passed source observation does not establish whole AISF control compliance.</p>"
        )
    else:
        result.append(
            "<p><strong>Additional AI check; AISF mapping not established.</strong> "
            + text(check["unmapped_reason"])
            + "</p>"
        )
    result.append(
        '<details class="finding-more"><summary>Complete source observation and alias provenance</summary><dl>'
    )
    result.extend(field(key, val) for key, val in sorted(check["observation"].items()))
    result.append("</dl></details></div>")
    return "".join(result)


STYLE = """<style>
#aisf-context,.aisf-source-context {overflow-wrap:anywhere}
#aisf-context > p {margin:12px 0}
#aisf-context dl,.aisf-source-context dl {margin:8px 0}
#aisf-context dt,.aisf-source-context dt {font-weight:600}
#aisf-context dd,.aisf-source-context dd {white-space:pre-wrap;margin:0 0 8px}
</style>"""

SCRIPT = r"""<script>
(() => {
const data = JSON.parse(document.getElementById('aisf-data').textContent);
function download(content,type,name) {
 const url=URL.createObjectURL(new Blob([content],{type}));
 const a=document.createElement('a');a.href=url;a.download=name;a.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
document.getElementById('aisf-json').addEventListener('click',()=>download(JSON.stringify(data,null,2),'application/json','aisf-checks.json'));
function csv(v) {
 let s=typeof v==='string'?v:JSON.stringify(v);
 if(/^[\s]*[=+\-@\t\r]/.test(s)) s="'"+s;
 return '"'+s.replace(/"/g,'""')+'"';
}
document.getElementById('aisf-csv').addEventListener('click',()=>{
 const rows=[['Record_Type','Check_ID','Status','Severity','Account_ID','Region','Execution_ID','Source_Owner','Finding','Finding_Details','Resource_ID','Resolution','Reference','Result_Kind','Evidence_Kind','Predicate','Limitations','AISF_Control_IDs','AISF_Mappings','Unmapped_Reason','Observation','Gap','Source_revision','Catalog_SHA256','Mapping_SHA256']];
 for(const c of data.checks)
  rows.push(['check',c.source_check_id,c.status,c.severity,c.account,c.region,c.execution_id,c.source_owner,c.finding,c.finding_details,c.resource,c.action_required,c.reference,c.result_kind,c.evidence_kind,c.predicate,c.limitations,c.aisf_control_ids,c.aisf_links,c.unmapped_reason,c.observation,'',data.source_revision,data.catalog_sha256,data.mapping_sha256]);
 for(const g of data.gaps)
  rows.push(['gap',g.source_check_id||'','','',g.account||'',g.region||'',g.execution_id||'',g.owner||'','','','','','','','','','','','','','',g,data.source_revision,data.catalog_sha256,data.mapping_sha256]);
 download(rows.map(r=>r.map(csv).join(',')).join('\r\n'),'text/csv;charset=utf-8','aisf-checks.csv');
});
})();
</script>"""
