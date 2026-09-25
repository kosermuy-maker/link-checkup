(() => {
  "use strict";
  const $ = (sel) => document.querySelector(sel);
  const params = new URLSearchParams(location.search);
  let lang = params.get("lang") || localStorage.getItem("lc-lang") || "en";
  if (!window.I18N[lang]) lang = "en";
  let lastReport = null;
  let lastError = null;

  const t = (key) => window.I18N[lang][key];

  function applyLang() {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document.title = lang === "zh" ? "可疑链接体检 · Link Checkup" : "Link Checkup · 可疑链接体检";
    document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    document.querySelectorAll("[data-i18n-title]").forEach((el) => { el.title = t(el.dataset.i18nTitle); });
    document.querySelectorAll("[data-lang]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === lang)));
    if (lastReport) render(lastReport);
    if (lastError) showError(lastError);
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function showError(err) {
    lastError = err;
    const box = $("#error");
    box.textContent = typeof err === "string" ? err : err[lang] || err.en;
    box.hidden = false;
  }

  function render(r) {
    lastReport = r;
    $("#result").hidden = false;
    const gauge = $("#gauge");
    gauge.style.setProperty("--score", String(r.score));
    gauge.dataset.level = r.level;
    $("#score").textContent = String(r.score);
    const level = $("#level");
    level.textContent = t("level")[r.level];
    level.dataset.level = r.level;
    $("#explanation").textContent = r.explanation[lang];
    $("#meta").textContent = t("meta")(r);

    // redirect chain
    const redirects = r.checks.find((c) => c.check === "redirects");
    const hops = (redirects && redirects.data && redirects.data.hops) || [];
    const chain = $("#chain");
    const ol = $("#hops");
    ol.replaceChildren();
    if (hops.length > 1 || (hops[0] && hops[0].location)) {
      hops.forEach((h) => {
        const li = el("li");
        li.append(el("code", "status", h.status === null ? "—" : String(h.status)), el("span", "hop-url", h.url));
        ol.append(li);
      });
      if (r.finalUrl && !hops.some((h) => h.url === r.finalUrl)) {
        const li = el("li", "final");
        li.append(el("code", "status", "→"), el("span", "hop-url", r.finalUrl));
        ol.append(li);
      }
      chain.hidden = false;
    } else chain.hidden = true;

    // checks
    const wrap = $("#checks");
    wrap.replaceChildren();
    r.checks.forEach((c) => {
      const card = el("article", "card");
      card.dataset.status = c.status;
      const head = el("header");
      const pts = c.findings.reduce((s, f) => s + f.points, 0);
      head.append(el("h3", "", t("checks")[c.check] || c.check));
      const badge = el("span", "badge", t("status")[c.status] + (pts ? ` · +${pts}` : ""));
      badge.dataset.status = c.status;
      head.append(badge);
      card.append(head);
      const ul = el("ul");
      c.findings.forEach((f) => {
        const li = el("li");
        li.dataset.severity = f.severity;
        const title = el("div", "f-title");
        title.append(el("span", "sev", ""), el("strong", "", f.title[lang]));
        if (f.points) title.append(el("span", "pts", `+${f.points}`));
        li.append(title, el("p", "f-detail", f.detail[lang]));
        ul.append(li);
      });
      card.append(ul);
      wrap.append(card);
    });
  }

  async function check(url) {
    $("#error").hidden = true;
    lastError = null;
    $("#result").hidden = true;
    $("#loading").hidden = false;
    $("#go").disabled = true;
    try {
      const res = await fetch("api/check", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) showError(data.error || t("networkError"));
      else render(data);
    } catch {
      showError(t("networkError"));
    } finally {
      $("#loading").hidden = true;
      $("#go").disabled = false;
    }
  }

  $("#form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("#url").value.trim();
    if (v) check(v);
  });
  document.querySelectorAll("[data-example]").forEach((b) =>
    b.addEventListener("click", () => {
      $("#url").value = b.dataset.example;
      check(b.dataset.example);
    }),
  );
  document.querySelectorAll("[data-lang]").forEach((b) =>
    b.addEventListener("click", () => {
      lang = b.dataset.lang;
      localStorage.setItem("lc-lang", lang);
      applyLang();
    }),
  );

  applyLang();
  const preset = params.get("url");
  if (preset) {
    $("#url").value = preset;
    check(preset);
  }
})();
