// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://dgellow.github.io',
	base: '/mcp-front',
	integrations: [
		starlight({
			title: 'MCP Front',
			description: 'OAuth 2.1 authenticated proxy for Model Context Protocol servers',
			logo: {
				alt: 'MCP Front Logo',
				src: './src/assets/animated-logo.svg',
			},
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/dgellow/mcp-front' },
			],
			sidebar: [
				{
					label: 'Start Here',
					items: [
						{ label: 'Introduction', slug: 'index' },
						{ label: 'Getting Started', slug: 'getting-started' },
						{ label: 'Architecture', slug: 'architecture' },
					],
				},
				{
					label: 'Configuration',
					items: [
						{ label: 'Overview', slug: 'config/overview' },
						{ label: 'Bearer Token Auth', slug: 'config/bearer-token' },
						{ label: 'OAuth 2.1 Auth', slug: 'config/oauth' },
						{ label: 'MCP Servers', slug: 'config/mcp-servers' },
						{ label: 'Environment Variables', slug: 'config/environment' },
					],
				},
				{
					label: 'Deployment',
					items: [
						{ label: 'Docker', slug: 'deployment/docker' },
						{ label: 'Docker Compose', slug: 'deployment/docker-compose' },
						{ label: 'Google Cloud Run', slug: 'deployment/cloud-run' },
						{ label: 'Production Setup', slug: 'deployment/production' },
					],
				},
				{
					label: 'OAuth Guide',
					items: [
						{ label: 'OAuth 2.1 Overview', slug: 'oauth/overview' },
						{ label: 'Google Workspace Setup', slug: 'oauth/google-workspace' },
						{ label: 'Firestore Configuration', slug: 'oauth/firestore' },
						{ label: 'Security Best Practices', slug: 'oauth/security' },
					],
				},
				{
					label: 'API Reference',
					items: [
						{ label: 'Endpoints', slug: 'api/endpoints' },
						{ label: 'Authentication', slug: 'api/authentication' },
						{ label: 'SSE Protocol', slug: 'api/sse-protocol' },
					],
				},
				{
					label: 'Development',
					items: [
							{ label: 'Testing', slug: 'dev/testing' },
						{ label: 'Architecture Decisions', slug: 'dev/architecture-decisions' },
					],
				},
			],
			customCss: ['./src/styles/custom.css'],
			components: {
				Header: './src/components/CustomHeader.astro',
			},
		}),
	],
});
