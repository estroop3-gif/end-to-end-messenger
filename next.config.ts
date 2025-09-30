import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  // Exclude windows-installer directory from Next.js build
  webpack: (config, { isServer }) => {
    config.watchOptions = {
      ...config.watchOptions,
      ignored: ['**/windows-installer/**', '**/node_modules/**']
    };

    // Completely exclude windows-installer from module resolution
    config.resolve = config.resolve || {};
    config.resolve.alias = {
      ...config.resolve.alias,
      'windows-installer': false,
    };

    // Add exclusion rule for TypeScript files in windows-installer
    config.module.rules.push({
      test: /windows-installer.*\.(ts|tsx|js|jsx)$/,
      use: 'ignore-loader'
    });

    return config;
  },
};

export default nextConfig;
