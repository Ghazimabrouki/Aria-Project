/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: "http://api:8001/api/v1/:path*",
      },
      {
        source: "/monitor/:path*",
        destination: "http://api:8001/monitor/:path*",
      },
      {
        source: "/api/monitoring/:path*",
        destination: "http://api:8001/api/monitoring/:path*",
      },
    ];
  },
};

export default nextConfig
