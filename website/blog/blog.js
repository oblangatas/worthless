function togglePost(id) {
  const full = document.getElementById(id);
  const btn = document.getElementById("btn-" + id);
  if (!full || !btn) return;

  const open = full.classList.contains("visible");
  full.classList.toggle("visible", !open);
  btn.classList.toggle("open", !open);
  btn.setAttribute("aria-expanded", String(!open));

  const label = btn.querySelector(".expand-label");
  if (label) {
    label.textContent = open ? "Read article" : "Collapse article";
  }
}

document.querySelectorAll(".expand-btn[aria-controls]").forEach((btn) => {
  btn.addEventListener("click", () => {
    togglePost(btn.getAttribute("aria-controls"));
  });
});

window.addEventListener("DOMContentLoaded", () => {
  const routes = {
    "#why-i-built-worthless": "p0",
    "#the-landscape": "p4",
    "#introducing-worthless": "p1",
    "#split-key-crypto": "p2",
  };
  const target = routes[location.hash];
  if (target) togglePost(target);
});
