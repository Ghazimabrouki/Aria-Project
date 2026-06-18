import type { Metadata, Viewport } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
import Script from 'next/script'
import { AuthProvider } from '@/lib/auth-context'
import './globals.css'

const inter = Inter({ 
  subsets: ["latin"],
  variable: "--font-inter",
});

const jetbrainsMono = JetBrains_Mono({ 
  subsets: ["latin"],
  variable: "--font-jetbrains",
});

export const viewport: Viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#f8fafc' },
    { media: '(prefers-color-scheme: dark)', color: '#0a0a14' },
  ],
}

export const metadata: Metadata = {
  title: 'ARIA - Security Operations Platform | Huawei',
  description: 'ARIA - Advanced Response & Investigation Automation Platform by Huawei. Licensed to Ghazi Mabrouki.',
  generator: 'v0.app',
  icons: {
    icon: '/aria-logo.png',
    apple: '/aria-logo.png',
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <>
      <Script id="unregister-sw" strategy="beforeInteractive">
        {`
          if (typeof navigator !== 'undefined' && navigator.serviceWorker) {
            navigator.serviceWorker.getRegistrations().then(function(registrations) {
              registrations.forEach(function(registration) {
                registration.unregister();
              });
            });
          }
        `}
      </Script>
      <html lang="en" suppressHydrationWarning className="bg-background">
        <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased`}>
          <AuthProvider>
            {children}
          </AuthProvider>
          {process.env.NODE_ENV === 'production' && <Analytics />}
        </body>
      </html>
    </>
  )
}
