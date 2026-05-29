const SHOW_DRAFT_POSTS = false;

const RED_POSTS = [
  {
    title: "How leaked AI keys get reused",
    tag: "Draft",
    href: "#",
    published: false,
    summary: "A future attacker-view walkthrough. Not linked publicly until reviewed and sourced."
  },
  {
    title: "Provider budgets are not blast-radius controls",
    tag: "Draft",
    href: "#",
    published: false,
    summary: "A future proof post about why token and billing controls need precise language."
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
    item.innerHTML = `
      <small>${post.tag}</small>
      <a href="${post.href}">${post.title}</a>
      <p>${post.summary}</p>
    `;
    list.appendChild(item);
  });
}

renderRedPosts();
