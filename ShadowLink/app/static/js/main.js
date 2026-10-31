/* Shared helpers. All dynamic content is inserted with textContent to avoid XSS. */
window.SL = (function () {
  const token = () => {
    const m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : "";
  };

  async function api(url, options = {}) {
    const opts = Object.assign({ credentials: "same-origin", headers: {} }, options);
    opts.headers = Object.assign({ "Accept": "application/json", "X-CSRFToken": token() }, opts.headers);
    if (opts.body && typeof opts.body !== "string") {
      opts.body = JSON.stringify(opts.body);
      opts.headers["Content-Type"] = "application/json";
    }
    const resp = await fetch(url, opts);
    let data = null;
    try { data = await resp.json(); } catch (e) { /* non-JSON */ }
    if (!resp.ok) {
      const err = new Error((data && data.error) || "Request failed (" + resp.status + ").");
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) e.setAttribute(k, v);
    }
    for (const c of children) if (c != null) e.append(c);
    return e;
  }

  function riskClass(cat) {
    if (cat === "High estimated risk") return "risk-high";
    if (cat === "Medium estimated risk") return "risk-medium";
    if (cat === "Lower estimated risk") return "risk-lower";
    return "risk-insufficient";
  }
  const riskBadge = (cat) => el("span", { class: "badge-risk " + riskClass(cat), text: cat || "n/a" });
  const fmtDate = (iso) => new Date(iso).toLocaleString();

  const toggle = document.getElementById("sidebar-toggle");
  if (toggle) toggle.addEventListener("click", () => document.getElementById("sidebar").classList.toggle("open"));

  return { api, el, riskBadge, fmtDate, riskClass };
})();
