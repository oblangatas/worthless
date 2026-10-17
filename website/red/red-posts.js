const SHOW_DRAFT_POSTS = false;

// Drafts never ship in page source: add a post here only once it's published.
const RED_POSTS = [];

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
