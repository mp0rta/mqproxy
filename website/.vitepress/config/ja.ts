import { DefaultTheme, LocaleSpecificConfig } from 'vitepress'

export const ja: LocaleSpecificConfig<DefaultTheme.Config> & { label: string; lang: string } = {
  label: '日本語',
  lang: 'ja',
  description: 'Multipath QUIC 上に構築されたマルチパス・アプリケーションプロキシ／アクセラレータ',

  themeConfig: {
    nav: [
      { text: 'ガイド', link: '/ja/guide/introduction' },
      { text: 'リファレンス', link: '/ja/reference/options' },
      { text: 'ベンチマーク', link: '/ja/benchmarks/' },
    ],

    footer: {
      message: 'Apache License 2.0 に基づき公開',
      copyright: '本ソフトウェアは現状有姿（AS IS）で提供され、いかなる保証も行いません。利用は自己責任で行ってください。',
    },

    sidebar: {
      '/ja/guide/': [
        {
          text: 'はじめに',
          items: [
            { text: '概要', link: '/ja/guide/introduction' },
            { text: 'ソースからのビルド', link: '/ja/guide/building' },
            { text: 'クイックスタート', link: '/ja/guide/quick-start' },
          ],
        },
        {
          text: '動作モード',
          items: [
            { text: 'TCP プロキシ', link: '/ja/guide/tcp-proxy' },
            { text: 'HTTP ゲートウェイ', link: '/ja/guide/http-gateway' },
            { text: 'UDP リレー', link: '/ja/guide/udp-relay' },
            { text: '透過キャプチャ', link: '/ja/guide/transparent-capture' },
            { text: 'TLS MITM', link: '/ja/guide/tls-mitm' },
          ],
        },
        {
          text: '運用',
          items: [
            { text: 'レジリエンス', link: '/ja/guide/resilience' },
            { text: '設定ファイル', link: '/ja/guide/configuration' },
            { text: 'インストール', link: '/ja/guide/installation' },
          ],
        },
      ],
      '/ja/reference/': [
        {
          text: 'リファレンス',
          items: [
            { text: 'オプションリファレンス', link: '/ja/reference/options' },
            { text: 'オブザーバビリティ', link: '/ja/reference/observability' },
            { text: 'セキュリティモデル', link: '/ja/reference/security-model' },
          ],
        },
      ],
    },
  },
}
