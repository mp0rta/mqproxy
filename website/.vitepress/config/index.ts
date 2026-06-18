import { defineConfig } from 'vitepress'
import { en } from './en'
import { ja } from './ja'

export default defineConfig({
  title: 'mqproxy',
  lastUpdated: true,
  cleanUrls: true,
  srcExclude: ['README.md'],

  head: [
    ['link', { rel: 'canonical', href: 'https://proxy.mqvpn.org' }],
  ],

  locales: {
    root: en,
    ja: ja,
  },

  themeConfig: {
    socialLinks: [
      { icon: 'github', link: 'https://github.com/mp0rta/mqproxy' },
    ],

    search: {
      provider: 'local',
    },
  },
})
