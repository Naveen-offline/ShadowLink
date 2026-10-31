(function () {
  const body = document.getElementById("h-body");
  const state = { page: 1 };
  const $ = (id) => document.getElementById(id);
  const selected = new Set();

  function syncBulk() { $("bulk-delete").disabled = selected.size === 0; }

  async function load() {
    const p = new URLSearchParams({ page: state.page, sort: $("f-sort").value });
    if ($("f-q").value.trim()) p.set("q", $("f-q").value.trim());
    if ($("f-cat").value) p.set("category", $("f-cat").value);
    try {
      const d = await SL.api("/api/history?" + p);
      selected.clear(); syncBulk(); $("select-all").checked = false;
      $("h-count").textContent = d.total + " scan" + (d.total === 1 ? "" : "s");
      $("page-info").textContent = "Page " + d.page + " of " + d.pages;
      $("prev").disabled = d.page <= 1; $("next").disabled = d.page >= d.pages;
      body.replaceChildren();
      if (!d.items.length) {
        body.append(SL.el("tr", {}, SL.el("td", { colspan: "7", class: "text-muted", text: "No scans match." })));
        return;
      }
      for (const s of d.items) {
        const cb = SL.el("input", { type: "checkbox", class: "form-check-input", "aria-label": "Select scan " + s.id });
        cb.addEventListener("change", () => { cb.checked ? selected.add(s.id) : selected.delete(s.id); syncBulk(); });
        body.append(SL.el("tr", {},
          SL.el("td", {}, cb),
          SL.el("td", { text: s.registered_domain || "" }),
          SL.el("td", { class: "url-cell", title: s.submitted_url, text: s.submitted_url }),
          SL.el("td", { text: String(s.risk_score) }),
          SL.el("td", {}, SL.riskBadge(s.risk_category)),
          SL.el("td", { text: SL.fmtDate(s.created_at) }),
          SL.el("td", { class: "text-nowrap" },
            SL.el("a", { class: "btn btn-sm btn-outline-soft me-1", href: "/results/" + s.id, text: "View" }),
            SL.el("a", { class: "btn btn-sm btn-outline-soft me-1", href: "/api/report/" + s.id + "/pdf", "aria-label": "Export PDF", title: "Export PDF" }, SL.el("i", { class: "fa-solid fa-file-pdf" })),
            SL.el("button", { class: "btn btn-sm btn-outline-danger", "aria-label": "Delete scan " + s.id, onclick: () => del(s.id) }, SL.el("i", { class: "fa-solid fa-trash" })))));
      }
    } catch (e) {
      body.replaceChildren(SL.el("tr", {}, SL.el("td", { colspan: "7", class: "field-error", text: e.message })));
    }
  }

  async function del(id) {
    if (!confirm("Delete this scan record?")) return;
    try { await SL.api("/api/history/" + id, { method: "DELETE" }); load(); } catch (e) { alert(e.message); }
  }

  $("filter-form").addEventListener("submit", (e) => { e.preventDefault(); state.page = 1; load(); });
  $("prev").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); load(); });
  $("next").addEventListener("click", () => { state.page += 1; load(); });
  $("select-all").addEventListener("change", (e) => {
    body.querySelectorAll("input[type=checkbox]").forEach((c) => { c.checked = e.target.checked; c.dispatchEvent(new Event("change")); });
  });
  $("bulk-delete").addEventListener("click", async () => {
    if (!confirm("Delete " + selected.size + " selected scan(s)?")) return;
    try { await SL.api("/api/history/bulk-delete", { method: "POST", body: { ids: [...selected] } }); load(); } catch (e) { alert(e.message); }
  });
  load();
})();
