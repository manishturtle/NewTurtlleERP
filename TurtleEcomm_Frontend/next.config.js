/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  async rewrites() {
    return [
      // Handle tenant-specific routes
      {
        source: '/:tenant/tenant-admin/:path*',
        destination: '/[tenant]/tenant-admin/:path*',
      },
      // Handle tenant root
      {
        source: '/:tenant',
        destination: '/[tenant]',
      }
    ];
  },
}

module.exports = nextConfig
