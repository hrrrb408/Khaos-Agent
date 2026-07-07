/** @type {import('next').NextConfig} */
const nextConfig = {
  // Explicitly pin the workspace root so Next.js does not infer it from the
  // unrelated ~/package-lock.json found above this project.
  outputFileTracingRoot: __dirname,
};

module.exports = nextConfig;
