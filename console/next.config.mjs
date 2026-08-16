/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The Hub base URL is read server-side only (BFF) — never exposed to the browser.
  env: {},
};
export default nextConfig;
