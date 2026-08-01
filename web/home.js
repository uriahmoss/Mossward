const newsPanel = document.querySelector("#cve-news");
const feedStatus = document.querySelector("#feed-status");

const escapeHTML = (value) => String(value).replace(
  /[&<>"']/g,
  (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
);

function shortDate(value) {
  return new Intl.DateTimeFormat(undefined, {dateStyle: "medium"}).format(new Date(value));
}

async function loadIntelligence() {
  try {
    const [newsResponse, statusResponse] = await Promise.all([
      fetch("/api/intelligence/news"), fetch("/api/intelligence/status"),
    ]);
    if (!newsResponse.ok || !statusResponse.ok) throw new Error("request failed");
    const [items, status] = await Promise.all([newsResponse.json(), statusResponse.json()]);
    feedStatus.textContent = status.last_success
      ? `${status.database_cves.toLocaleString()} CVEs · updated ${shortDate(status.last_success)}`
      : "Feed not synced";
    newsPanel.innerHTML = items.length ? items.map((item) => `
      <article class="cve-news-card${item.relevance === "matched" ? " cve-news-relevant" : ""}">
        <div class="cve-news-meta">
          <span class="severity" data-severity="critical">CVSS ${item.cvss_score.toFixed(1)}</span>
          <span>${escapeHTML(shortDate(item.published_at))}</span>
        </div>
        <h3>${escapeHTML(item.id)}</h3>
        <div class="cve-badges">
          <span class="relevance-badge" data-relevance="${escapeHTML(item.relevance)}">${item.relevance === "matched" ? "Environment match" : "General critical"}</span>
          ${item.known_exploited ? '<span class="kev-badge">Known exploited</span>' : ""}
        </div>
        ${item.evidence ? `<p class="cve-evidence">${escapeHTML(item.evidence)}</p>` : ""}
        <p>${escapeHTML(item.description)}</p>
        <a href="${escapeHTML(item.source_url)}" target="_blank" rel="noopener noreferrer">View NVD record ↗</a>
      </article>
    `).join("") : `
      <div class="cve-news-empty"><strong>No local CVE intelligence yet</strong><span>Run <code>mossward cve sync</code> to import recent critical records from NVD.</span></div>`;
  } catch {
    feedStatus.textContent = "Feed unavailable";
    newsPanel.innerHTML = '<div class="cve-news-empty"><strong>Could not load CVE intelligence</strong><span>The scanner remains available.</span></div>';
  }
}

loadIntelligence();
