import type { Metadata } from "next";
import { Toaster } from "sonner";
import { Geist, JetBrains_Mono, Space_Grotesk } from "next/font/google";
import "./globals.css";
import ReconStatusBannerContainer from "@/components/ReconStatusBannerContainer";

const geist = Geist({
  subsets: ["latin"],
  variable: "--font-geist",
});

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
});

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
    <html lang="en" className={`dark ${geist.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable}`}>
      <body className="bg-slate-950 text-slate-50 min-h-screen font-sans">
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
        <ReconStatusBannerContainer />
        <Toaster position="bottom-right" theme="dark" richColors />
      </body>
    </html>
  );
}
