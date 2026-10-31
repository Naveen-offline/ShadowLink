(function () {
  const COLORS = { high: "#EF4444", medium: "#F59E0B", lower: "#22C55E", insufficient: "#6366F1", accent: "#00E5FF" };
  const text = (id, v) => { document.getElementById(id).textContent = v; };

  function chartDefaults() {
    Chart.defaults.color = "#9FB0C8";
    Chart.defaults.borderColor = "rgba(148,163,184,.15)";
    Chart.defaults.font.family = "Inter, system-ui, sans-serif";
  }

  function renderRecent(rows) {
    const body = document.getElementById("recent-body");
    body.replaceChildren();
    if (!rows.length) {
      body.append(SL.el("tr", {}, SL.el("td", { colspan: "5", class: "text-muted", text: "No scans yet. Scan your first URL to see activity here." })));
      return;
    }
    for (const s of rows) {
      body.append(SL.el("tr", {},
        SL.el("td", { text: s.registered_domain || "" }),
        SL.el("td", { text: String(s.risk_score) }),
        SL.el("td", {}, SL.riskBadge(s.risk_category)),
        SL.el("td", { text: SL.fmtDate(s.created_at) }),
        SL.el("td", {}, SL.el("a", { href: "/results/" + s.id, class: "btn btn-sm btn-outline-soft", text: "View" }))));
    }
  }

  async function load() {
    chartDefaults();
    const d = await SL.api("/api/dashboard/stats");
    text("s-total", d.total); text("s-high", d.high); text("s-medium", d.medium); text("s-lower", d.lower);

    const dist = [d.high, d.medium, d.lower, d.insufficient];
    if (d.total === 0) document.getElementById("dist-empty").classList.remove("d-none");
    new Chart(document.getElementById("chart-dist"), {
      type: "doughnut",
      data: { labels: ["High", "Medium", "Lower", "Insufficient evidence"], datasets: [{ data: dist, backgroundColor: [COLORS.high, COLORS.medium, COLORS.lower, COLORS.insufficient], borderWidth: 0 }] },
      options: { maintainAspectRatio: false, cutout: "68%", plugins: { legend: { position: "bottom" } } },
    });

    const labels = d.daily.labels.map((l) => l.slice(5));
    new Chart(document.getElementById("chart-daily"), {
      type: "bar",
      data: { labels, datasets: [{ label: "Scans", data: d.daily.counts, backgroundColor: "rgba(0,229,255,.55)", borderRadius: 6 }] },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
    });

    new Chart(document.getElementById("chart-trend"), {
      type: "line",
      data: { labels, datasets: [{ label: "Average risk score", data: d.trend.avg_score, borderColor: COLORS.accent, backgroundColor: "rgba(0,229,255,.12)", fill: true, tension: .3, spanGaps: true, pointRadius: 3 }] },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { min: 0, max: 100 } } },
    });
    renderRecent(d.recent);
  }

  load().catch((e) => {
    document.getElementById("recent-body").replaceChildren(SL.el("tr", {}, SL.el("td", { colspan: "5", class: "field-error", text: e.message })));
  });
})();
