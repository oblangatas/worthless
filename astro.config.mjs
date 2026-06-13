import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://docs.wless.io',
  integrations: [
    starlight({
      title: 'Worthless',
      description: 'Make API keys worthless to steal.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/shacharm2/worthless' },
      ],
      editLink: {
        baseUrl: 'https://github.com/shacharm2/worthless/edit/main/',
      },
      sidebar: [
        {
          label: 'Get Started',
          items: [
            { label: 'Welcome', slug: 'index' },
          ],
        },
        {
          label: 'Install',
          items: [
            { label: 'Solo Developer', slug: 'install-solo' },
            { label: 'Docker', slug: 'install-docker' },
            { label: 'Self-Hosted', slug: 'install-self-hosted' },
            { label: 'Claude Code / Cursor / Windsurf', slug: 'install-mcp' },
            { label: 'GitHub Actions', slug: 'install-github-actions' },
            { label: 'Install Security', slug: 'install-security' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Wire Protocol', slug: 'protocol' },
            { label: 'Security Model', slug: 'security' },
            { label: 'Recovery', slug: 'recovery' },
          ],
        },
      ],
      lastUpdated: true,
    }),
  ],
});
