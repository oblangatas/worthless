const NEWS_FEED_URL = "https://gist.githubusercontent.com/oblangatas/7f6e2293b540004c4a733258a2461800/raw/news-feed.json";
const NEWS_FEED_FALLBACK_URL = "news-feed.json";
const NEWS_FEED_TIMEOUT_MS = 5000;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderFeedRows(entries, options = {}) {
  const hiddenAttrs = options.hidden ? ' tabindex="-1" aria-hidden="true"' : "";
  return entries.map((entry) => {
    const date = entry.date ? `<span class="feed-date">${escapeHtml(entry.date)}</span>` : '<span class="feed-date"></span>';
    const impact = entry.impact ? `<span class="feed-impact">└ ${escapeHtml(entry.impact)}</span>` : "";
    return `<a href="${escapeHtml(safeHref(entry.href))}" target="_blank" rel="noopener noreferrer" class="feed-row"${hiddenAttrs}><span class="feed-src">${escapeHtml(entry.source)}</span><span class="feed-main"><span class="feed-desc">${escapeHtml(entry.desc)}</span>${impact}</span>${date}</a>`;
  }).join("");
}

function safeHref(value) {
  const href = String(value || "").trim();
  if (href.startsWith("/") && !href.startsWith("//")) return href;

  try {
    const parsed = new URL(href);
    return ["http:", "https:", "mailto:"].includes(parsed.protocol) ? href : "#";
  } catch (_error) {
    return "#";
  }
}

function cacheBustedUrl(url) {
  if (!String(url).startsWith("http")) return url;
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}v=${Date.now()}`;
}

function setNewsFeed(entries) {
  const feed = document.getElementById("news-feed");
  if (!feed) return;

  const usableEntries = Array.isArray(entries) ? entries.filter((entry) => entry && entry.source && entry.desc && entry.href) : [];
  if (usableEntries.length === 0) {
    feed.innerHTML = '<div class="feed-empty">No incidents loaded.</div>';
    return;
  }

  feed.innerHTML = renderFeedRows(usableEntries) + renderFeedRows(usableEntries, { hidden: true });
}

async function fetchNewsFeed(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), NEWS_FEED_TIMEOUT_MS);

  try {
    const response = await fetch(cacheBustedUrl(url), { cache: "no-store", signal: controller.signal });
    if (!response.ok) {
      throw new Error(`Feed request failed: ${response.status}`);
    }

    return response.json();
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(`Feed request timed out after ${NEWS_FEED_TIMEOUT_MS}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function loadNewsFeed() {
  try {
    setNewsFeed(await fetchNewsFeed(NEWS_FEED_URL));
  } catch (_remoteError) {
    try {
      setNewsFeed(await fetchNewsFeed(NEWS_FEED_FALLBACK_URL));
    } catch (_fallbackError) {
      setNewsFeed([]);
    }
  }
}

loadNewsFeed();
