const sentinels = Array.from(document.querySelectorAll("[data-beat-target]"));
const hero = document.querySelector(".hero");
const cinema = document.querySelector(".cinema");
const beatLabel = document.getElementById("beat-label");
const beatTitle = document.getElementById("beat-title");
const beatBody = document.getElementById("beat-body");
const installCopy = document.getElementById("copy-install");
const installStatus = document.getElementById("copy-install-status");
const installHelp = document.getElementById("copy-install-help");
const promiseExplainer = document.querySelector(".promise-explainer");
const promiseSummary = promiseExplainer?.querySelector("summary");
const receiptRail = document.querySelector(".receipt-rail");
const receiptPause = document.getElementById("receipt-pause");
const installCommand = "curl -sSL https://worthless.sh | sh";
const reduceMotion = window.matchMedia(
  "(prefers-reduced-motion: reduce)",
).matches;
const beats = [
  {
    label: "Protect",
    title: "Not your real key.",
    body: "Worthless leaves a lookalike in .env. The working route stays local.",
  },
  {
    label: "Leak",
    title: "Your AI pushes it.",
    body: "A key-looking value lands in GitHub, chat, logs, or generated code.",
  },
  {
    label: "Try it",
    title: "The leaked key fails.",
    body: "Someone tries the copied .env value. It cannot call the provider alone.",
  },
  {
    label: "Continue",
    title: "Your AI keeps working.",
    body: "Your app still works through Worthless. Investigate, rotate if needed.",
  },
];
let currentBeat = "0";

function setBeat(beat) {
  const next = beats[Number(beat)];
  if (!next || beat === currentBeat) return;
  currentBeat = beat;
  document.body.setAttribute("data-beat", beat);
  document.documentElement.style.setProperty("--beat", beat);
  beatLabel.textContent = next.label;
  beatTitle.textContent = next.title;
  beatBody.textContent = next.body;
}

function clamp(value, min = 0, max = 1) {
  return Math.min(max, Math.max(min, value));
}

function updateVisualTransition() {
  const heroHeight = hero.getBoundingClientRect().height || window.innerHeight;
  const heroProgress = clamp(window.scrollY / (heroHeight * 0.92));
  const cinemaTop = cinema.getBoundingClientRect().top;
  const terminalEnter = clamp(
    (window.innerHeight - cinemaTop) / (window.innerHeight * 0.55),
  );
  const markOpacity = clamp(1 - heroProgress * 1.15);
  document.documentElement.style.setProperty(
    "--hero-mark-opacity",
    markOpacity.toFixed(3),
  );
  document.documentElement.style.setProperty(
    "--terminal-enter",
    terminalEnter.toFixed(3),
  );
  document.documentElement.style.setProperty(
    "--terminal-scale",
    (0.955 + terminalEnter * 0.045).toFixed(3),
  );
}

const observer = new IntersectionObserver(
  (entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    const beat = visible.target.getAttribute("data-beat-target");
    setBeat(beat);
  },
  {
    rootMargin: "-35% 0px -45% 0px",
    threshold: [0, 0.25, 0.5, 0.75, 1],
  },
);
sentinels.forEach((el) => observer.observe(el));

function syncPromiseDisclosure() {
  promiseSummary?.setAttribute(
    "aria-expanded",
    String(Boolean(promiseExplainer?.open)),
  );
}

promiseSummary?.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  event.preventDefault();
  promiseExplainer.open = !promiseExplainer.open;
});
promiseExplainer?.addEventListener("toggle", syncPromiseDisclosure);
syncPromiseDisclosure();

function showCopiedState() {
  installHelp.hidden = true;
  installStatus.textContent = "Install command copied.";
  installCopy.classList.add("is-copied");
  installCopy.setAttribute("aria-label", "Install command copied");
  window.setTimeout(() => {
    installCopy.classList.remove("is-copied");
    installCopy.setAttribute(
      "aria-label",
      "Copy install command: " + installCommand,
    );
  }, 1600);
}

installCopy?.addEventListener("click", async () => {
  installHelp.hidden = true;
  const copyFromTextarea = () => {
    const textarea = document.createElement("textarea");
    textarea.value = installCommand;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.inset = "0 auto auto 0";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } finally {
      textarea.remove();
    }
    return copied;
  };

  try {
    if (!navigator.clipboard?.writeText) {
      throw new Error("Clipboard API unavailable");
    }
    await navigator.clipboard.writeText(installCommand);
    showCopiedState();
  } catch (_error) {
    if (copyFromTextarea()) {
      showCopiedState();
    } else {
      installHelp.hidden = false;
      installStatus.textContent = "Copy unavailable. Use the install guide below.";
      installCopy.setAttribute(
        "aria-label",
        "Copy unavailable. Use the install guide below.",
      );
    }
  }
});

receiptPause?.addEventListener("click", () => {
  const paused = receiptRail?.classList.toggle("is-paused") || false;
  receiptPause.setAttribute("aria-pressed", String(paused));
  receiptPause.textContent = paused ? "Resume feed" : "Pause feed";
});

const prompt = encodeURIComponent(
  "Please audit the Worthless installer script before I run it. " +
    "Check for data exfiltration, privilege escalation, persistence, " +
    "obfuscation, and unsafe downloads. Raw script: " +
    "https://raw.githubusercontent.com/shacharm2/worthless/main/install.sh",
);
const auditUrls = {
  claude: "https://claude.ai/new?q=" + prompt,
  chatgpt: "https://chatgpt.com/?q=" + prompt,
  gemini: "https://gemini.google.com/app?q=" + prompt,
  grok: "https://grok.com/?q=" + prompt,
};
document.querySelectorAll("[data-audit]").forEach((link) => {
  link.href = auditUrls[link.dataset.audit];
  link.target = "_blank";
  link.rel = "noopener noreferrer";
});

if (!reduceMotion) {
  updateVisualTransition();
  window.addEventListener("scroll", updateVisualTransition, { passive: true });
  window.addEventListener("resize", updateVisualTransition);
}
