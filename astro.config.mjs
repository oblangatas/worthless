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
          label: 'Install — by platform',
          items: [
            { label: 'Pick your platform', slug: 'install' },
            { label: 'macOS', slug: 'install/mac' },
            { label: 'Linux', slug: 'install/linux' },
            { label: 'Windows (WSL2)', slug: 'install/wsl' },
            { label: 'Docker (app in a container)', slug: 'install/docker' },
            { label: 'Agent schema', slug: 'install/agent-schema' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Wire Protocol', slug: 'protocol' },
            { label: 'Security Model', slug: 'security' },
            { label: 'Recovery', slug: 'recovery' },
            { label: 'Uninstall', slug: 'uninstall' },
            { label: 'Uninstall Contract', slug: 'uninstall-contract' },
          ],
        },
      ],
      lastUpdated: true,
    }),
  ],
});
