# mqproxy website

The mqproxy documentation site, built with [VitePress](https://vitepress.dev). Bilingual (English at `/`, Japanese under `/ja/`). Content is a re-organized port of the repository `README.md`.

## Local development

```bash
cd website
npm install
npm run docs:dev        # dev server with hot reload
npm run docs:build      # production build → .vitepress/dist
npm run docs:preview    # preview the production build locally
```

## Structure

```
website/
  index.md                 # EN home (hero + features)
  guide/                   # EN guide pages
  reference/               # EN reference pages
  ja/                      # JA mirror (index.md, guide/, reference/)
  .vitepress/
    config/
      index.ts             # shared config (title, locales, search, social)
      en.ts                # English locale: nav, sidebar, footer
      ja.ts                # Japanese locale: nav, sidebar, footer
    theme/index.ts         # default theme
```

To add a page: create the `.md` under `guide/` or `reference/` (and its `ja/` mirror), then add it to the `sidebar` in `.vitepress/config/en.ts` and `ja.ts`.

## Deploy

Deployed to Cloudflare Pages (Git integration) at **https://proxy.mqvpn.org** — root directory `website`, build `npm run docs:build`, output `.vitepress/dist`. Rebuilds on every push to `main`.
