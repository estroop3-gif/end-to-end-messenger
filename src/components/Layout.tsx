'use client'

import { ReactNode, useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Menu, X, Shield, Book, Download, Heart, Scale, Info, ChevronRight } from 'lucide-react'

interface LayoutProps {
  children: ReactNode
  showPrayer?: boolean
}

const navigation = [
  { name: 'Home', href: '/', icon: Shield },
  { name: 'Safety Guide', href: '/safety', icon: Shield },
  { name: 'Downloads', href: '/downloads', icon: Download },
  { name: 'Scripture', href: '/scripture', icon: Book },
  { name: 'Prayer', href: '/prayer', icon: Heart },
  { name: 'Code of Conduct', href: '/conduct', icon: Scale },
  { name: 'How to Use', href: '/how-to-use', icon: Info },
  { name: 'Legal', href: '/legal', icon: Scale },
]

export default function Layout({
  children,
  showPrayer = false
}: LayoutProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const pathname = usePathname()

  const isActive = (href: string) => {
    if (href === '/') {
      return pathname === '/'
    }
    return pathname.startsWith(href)
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Modern Navigation */}
      <nav className="sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-primary-100">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo */}
            <div className="flex items-center">
              <Link href="/" className="flex items-center space-x-3 group">
                <div className="w-10 h-10 bg-accent-600 rounded-xl flex items-center justify-center group-hover:bg-accent-700 transition-colors duration-200">
                  <Shield className="h-5 w-5 text-white" />
                </div>
                <div className="flex flex-col">
                  <span className="text-lg font-semibold text-primary-900">JESUS IS KING</span>
                  <span className="text-xs text-primary-500 -mt-1">Secure Messaging</span>
                </div>
              </Link>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden lg:flex items-center space-x-1">
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={`nav-link group ${isActive(item.href) ? 'active' : ''}`}
                  >
                    <Icon className="h-4 w-4 mr-2" />
                    {item.name}
                  </Link>
                )
              })}
            </div>

            {/* CTA Button */}
            <div className="hidden md:flex">
              <Link href="/downloads" className="btn-primary">
                <Download className="h-4 w-4 mr-2" />
                Download
              </Link>
            </div>

            {/* Mobile menu button */}
            <div className="lg:hidden">
              <button
                type="button"
                className="p-2 rounded-lg text-primary-500 hover:bg-primary-50 hover:text-primary-700 transition-colors duration-200"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              >
                {mobileMenuOpen ? (
                  <X className="h-5 w-5" />
                ) : (
                  <Menu className="h-5 w-5" />
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="lg:hidden border-t border-primary-100 bg-white">
            <div className="px-4 py-3 space-y-1">
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={`flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                      isActive(item.href)
                        ? 'bg-accent-50 text-accent-700'
                        : 'text-primary-600 hover:bg-primary-50 hover:text-primary-900'
                    }`}
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    <Icon className="h-4 w-4 mr-3" />
                    {item.name}
                  </Link>
                )
              })}
              <div className="pt-2 mt-2 border-t border-primary-100">
                <Link
                  href="/downloads"
                  className="flex items-center px-3 py-2 rounded-lg bg-accent-600 text-white font-medium"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download App
                </Link>
              </div>
            </div>
          </div>
        )}
      </nav>

      {/* Prayer Banner */}
      {showPrayer && (
        <div className="bg-gradient-to-r from-accent-600 to-accent-700 text-white py-3">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-center">
            <Heart className="h-4 w-4 mr-2 flex-shrink-0" />
            <span className="text-sm font-medium text-center">
              &ldquo;Trust in the Lord with all your heart and lean not on your own understanding.&rdquo; - Proverbs 3:5
            </span>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1">
        {children}
      </main>

      {/* Modern Footer */}
      <footer className="bg-white border-t border-primary-100 mt-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            {/* Brand Section */}
            <div className="md:col-span-2">
              <div className="flex items-center space-x-3 mb-4">
                <div className="w-8 h-8 bg-accent-600 rounded-lg flex items-center justify-center">
                  <Shield className="h-4 w-4 text-white" />
                </div>
                <div>
                  <div className="text-lg font-semibold text-primary-900">JESUS IS KING</div>
                  <div className="text-sm text-primary-500">Secure Messaging Platform</div>
                </div>
              </div>
              <p className="text-primary-600 text-sm leading-relaxed max-w-md mb-4">
                A secure messaging and document platform designed with Biblical principles.
                All communications are protected by end-to-end encryption.
              </p>
              <div className="scripture-verse">
                &ldquo;He who dwells in the secret place of the Most High shall abide under the shadow of the Almighty.&rdquo; - Psalm 91:1
              </div>
            </div>

            {/* Platform Links */}
            <div>
              <h3 className="text-sm font-semibold text-primary-900 uppercase tracking-wider mb-4">
                Platform
              </h3>
              <div className="space-y-3">
                <Link href="/downloads" className="footer-link flex items-center">
                  Downloads
                  <ChevronRight className="h-3 w-3 ml-1" />
                </Link>
                <Link href="/safety" className="footer-link flex items-center">
                  Safety Guide
                  <ChevronRight className="h-3 w-3 ml-1" />
                </Link>
                <Link href="/how-to-use" className="footer-link flex items-center">
                  How to Use
                  <ChevronRight className="h-3 w-3 ml-1" />
                </Link>
              </div>
            </div>

            {/* Legal & Faith */}
            <div>
              <h3 className="text-sm font-semibold text-primary-900 uppercase tracking-wider mb-4">
                Legal & Faith
              </h3>
              <div className="space-y-3">
                <Link href="/legal" className="footer-link flex items-center">
                  Legal & Compliance
                  <ChevronRight className="h-3 w-3 ml-1" />
                </Link>
                <Link href="/conduct" className="footer-link flex items-center">
                  Code of Conduct
                  <ChevronRight className="h-3 w-3 ml-1" />
                </Link>
                <Link href="/scripture" className="footer-link flex items-center">
                  Scripture
                  <ChevronRight className="h-3 w-3 ml-1" />
                </Link>
                <Link href="/prayer" className="footer-link flex items-center">
                  Prayer
                  <ChevronRight className="h-3 w-3 ml-1" />
                </Link>
              </div>
            </div>
          </div>

          <div className="mt-12 pt-8 border-t border-primary-100">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center space-y-4 md:space-y-0">
              <p className="text-sm text-primary-500">
                © 2024 JESUS IS KING Platform. Built for educational purposes. Use responsibly.
              </p>
              <div className="alert-warning max-w-md">
                <div className="text-xs">
                  <strong>Educational Use Only:</strong> This platform is designed for educational purposes
                  and lawful communication. Users must comply with all applicable laws.
                </div>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}