import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Caponier - GitHub Repository Security Analysis",
  description: "Analyze the security of your GitHub repositories with comprehensive vulnerability scanning and risk assessment",
  keywords: ["security", "vulnerability", "github", "analysis", "cybersecurity", "dependencies"],
  authors: [{ name: "Caponier Team" }],
  openGraph: {
    title: "Caponier - GitHub Repository Security Analysis",
    description: "Analyze the security of your GitHub repositories with comprehensive vulnerability scanning and risk assessment",
    type: "website",
    url: "https://caponier.io",
  },
  twitter: {
    card: "summary_large_image",
    title: "Caponier - GitHub Repository Security Analysis",
    description: "Analyze the security of your GitHub repositories with comprehensive vulnerability scanning and risk assessment",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
