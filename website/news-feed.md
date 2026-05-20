# Homepage ticker feed

The homepage incident ticker loads from a public GitHub Gist:

- Edit URL: https://gist.github.com/shacharm2/7f6e2293b540004c4a733258a2461800
- Raw JSON URL: https://gist.githubusercontent.com/shacharm2/7f6e2293b540004c4a733258a2461800/raw/news-feed.json

Expected shape:

```json
[
  {
    "source": "HN",
    "desc": "Short incident headline",
    "date": "May 2026",
    "href": "https://example.com/story",
    "impact": "$128K billed"
  }
]
```

Notes:

- `source`, `desc`, and `href` are required.
- `date` may be an empty string.
- `impact` is optional. Use it only when the source clearly names a cost, loss, or bill.
- The site duplicates the entries in JavaScript for the seamless scroll loop.
- If the Gist is unavailable, the homepage falls back to the committed `website/news-feed.json`.
