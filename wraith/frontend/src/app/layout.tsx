import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Wraith — Autonomous Bug Bounty Pipeline",
  description: "Visualize attack surfaces and autonomous agent activity.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-50 min-h-screen">
        <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
          <div className="container mx-auto px-4 h-16 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 bg-indigo-600 rounded flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-500/20">W</div>
              <span className="text-xl font-black tracking-tight uppercase">Wraith</span>
            </div>
            <nav className="flex space-x-6 text-sm font-medium text-slate-400">
              <a href="/" className="hover:text-white transition-colors">Programs</a>
              <a href="#" className="hover:text-white transition-colors cursor-not-allowed">Settings</a>
            </nav>
          </div>
        </header>
        <main className="container mx-auto px-4 py-8">
          {children}
        </main>
      </body>
    </html>
  );
}
