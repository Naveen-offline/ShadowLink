(function () {
  const $ = (id) => document.getElementById(id);

  function kv(container, pairs) {
    container.replaceChildren();
    for (const [k, v] of pairs) {
      container.append(SL.el("dt", { text: k }), SL.el("dd", { text: v == null ? "n/a" : String(v) }));
    }
  }

  async function load() {
    const d = await SL.api("/api/admin/stats");
    const cards = $("a-cards"); cards.replaceChildren();
    for (const [label, val] of [["Users", d.users], ["Total scans", d.scans_total], ["Scans (24h)", d.scans_24h], ["High-risk scans", d.categories["High estimated risk"] || 0]]) {
      cards.append(SL.el("div", { class: "col-sm-6 col-xl-3" }, SL.el("div", { class: "sl-card stat" },
        SL.el("div", {}, SL.el("div", { class: "num", text: String(val) }), SL.el("div", { class: "lbl", text: label })))));
    }
    kv($("a-health"), [["Database", d.health.database ? "OK" : "Error"], ["Model loaded", d.health.model_loaded ? "Yes" : "No"], ["Model error", d.health.model_error || "None"]]);
    const t = d.model.test_metrics || {};
    kv($("a-model"), [["Version", d.model.version], ["Algorithm", d.model.name], ["Trained", d.model.trained_at],
      ["Test accuracy", t.accuracy], ["Test F1", t.f1], ["Test ROC-AUC", t.roc_auc]]);
    kv($("a-config"), Object.entries(d.config));
    const f = $("a-failures"); f.replaceChildren();
    if (!d.failures.length) f.append(SL.el("div", { class: "text-muted", text: "No failures recorded." }));
    for (const x of d.failures) f.append(SL.el("div", { class: "mb-1" }, SL.el("span", { class: "text-muted", text: new Date(x.at).toLocaleString() + " · " }), x.message));
    const logs = $("a-logs"); logs.replaceChildren();
    for (const l of d.logs) logs.append(SL.el("tr", {}, SL.el("td", { text: l.at.replace("T", " ").slice(0, 19) }), SL.el("td", { text: l.type }), SL.el("td", { text: l.message })));
  }

  $("reload-model").addEventListener("click", async () => {
    try { const r = await SL.api("/api/admin/reload-model", { method: "POST" }); alert(r.model_loaded ? "Model loaded: " + r.version : "Model unavailable: " + r.error); load(); } catch (e) { alert(e.message); }
  });
  $("purge").addEventListener("click", async () => {
    if (!confirm("Delete all scans older than the retention period?")) return;
    try { const r = await SL.api("/api/admin/purge-old", { method: "POST" }); alert("Deleted " + r.deleted + " scan(s)."); load(); } catch (e) { alert(e.message); }
  });
  load().catch((e) => alert(e.message));
})();
