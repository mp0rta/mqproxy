import { DefaultTheme, LocaleSpecificConfig } from 'vitepress'

export const en: LocaleSpecificConfig<DefaultTheme.Config> & { label: string; lang: string } = {
  label: 'English',
  lang: 'en',
  description: 'Multipath application proxy/accelerator built on Multipath QUIC',

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'Reference', link: '/reference/options' },
    ],

    footer: {
      message: 'Released under the Apache License 2.0',
      copyright: 'Provided "AS IS" without warranty of any kind. Use at your own risk.',
    },

    sidebar: {
      '/guide/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'Introduction', link: '/guide/introduction' },
            { text: 'Building from Source', link: '/guide/building' },
            { text: 'Quick Start', link: '/guide/quick-start' },
          ],
        },
        {
          text: 'Operating Modes',
          items: [
            { text: 'HTTP Gateway', link: '/guide/http-gateway' },
            { text: 'UDP Relay', link: '/guide/udp-relay' },
            { text: 'Transparent Capture', link: '/guide/transparent-capture' },
            { text: 'TLS MITM', link: '/guide/tls-mitm' },
          ],
        },
        {
          text: 'Operations',
          items: [
            { text: 'Resilience', link: '/guide/resilience' },
            { text: 'Configuration File', link: '/guide/configuration' },
            { text: 'Installation', link: '/guide/installation' },
          ],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Options Reference', link: '/reference/options' },
            { text: 'Observability', link: '/reference/observability' },
            { text: 'Security Model', link: '/reference/security-model' },
          ],
        },
      ],
    },
  },
}
