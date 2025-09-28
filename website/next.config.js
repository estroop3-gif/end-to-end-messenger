/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  env: {
    SITE_NAME: 'JESUS IS KING',
    SITE_DESCRIPTION: 'Secure Messaging & Document Platform guided by faith',
    DOWNLOAD_BASE_URL: process.env.DOWNLOAD_BASE_URL || 'https://github.com/jesus-is-king-messaging/releases',
    ESV_API_KEY: process.env.ESV_API_KEY || '', // Optional ESV API key
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'",
          },
        ],
      },
    ];
  },
}

module.exports = nextConfig