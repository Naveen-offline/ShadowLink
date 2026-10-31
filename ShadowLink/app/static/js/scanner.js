(function () {
  const form = document.getElementById("scan-form");
  const input = document.getElementById("url");
  const err = document.getElementById("scan-error");
  const loading = document.getElementById("scan-loading");
  const btn = document.getElementById("scan-btn");

  async function submit(ev) {
    if (ev) ev.preventDefault();
    err.textContent = "";
    const url = input.value.trim();
    if (!url) { err.textContent = "Please enter a URL."; input.focus(); return; }
    btn.disabled = true;
    loading.classList.remove("d-none");
    try {
      const data = await SL.api("/api/scan", { method: "POST", body: { url } });
      window.location.href = data.redirect_url;
    } catch (e) {
      loading.classList.add("d-none");
      btn.disabled = false;
      err.textContent = e.message;
      input.focus();
    }
  }

  form.addEventListener("submit", submit);
  // Landing-page handoff: auto-run when a URL was passed in.
  if (input.value.trim()) submit();
})();
