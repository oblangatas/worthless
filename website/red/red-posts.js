const SHOW_DRAFT_POSTS = false;

const RED_POSTS = [
  {
    title: "How leaked AI keys get reused",
    label: "Walkthrough",
    href: "#",
    published: false,
    summary: "A copied supported AI provider key gets tested fast. Worthless only changes the path if the leaked value was locked first.",
    verdict: "Copied locked supported AI-key material alone is not enough."
  },
  {
    title: "Provider budgets are not blast-radius controls",
    label: "Boundary",
    href: "#",
    published: false,
    summary: "Budget alerts help after usage starts. They are not the same thing as making copied material fail.",
    verdict: "A guardrail is not a hard spend cap."
  }
];

function renderRedPosts() {
  const list = document.getElementById("red-post-list");
  if (!list) return;

  const posts = RED_POSTS.filter((post) => post.published || SHOW_DRAFT_POSTS);
  if (posts.length === 0) return;

  list.innerHTML = "";
  posts.forEach((post) => {
    const item = document.createElement("article");
    item.className = "post";

    const label = document.createElement("div");
    label.className = "post-label";
    label.textContent = post.label;

    const link = document.createElement("a");
    link.href = post.href;
    link.textContent = post.title;

    const summary = document.createElement("p");
    summary.textContent = post.summary;

    const verdict = document.createElement("small");
    verdict.textContent = post.verdict;

    item.append(label, link, summary, verdict);
    list.appendChild(item);
  });
}

renderRedPosts();
