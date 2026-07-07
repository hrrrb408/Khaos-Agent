import "./styles/globals.css";
import "./styles/markdown.css";
import "highlight.js/styles/github-dark.css";

export const metadata = {
  title: "Khaos",
  description: "Khaos agent chat console",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
