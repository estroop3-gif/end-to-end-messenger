'use client'

import { ReactNode, useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Menu, X, Shield, Book, Download, Heart, Scale, Info } from 'lucide-react'

interface LayoutProps {
  children: ReactNode
  showPrayer?: boolean
}

const navigation = [
  { name: 'Home', href: '/', icon: Shield },
  { name: 'Safety & OpSec', href: '/safety', icon: Shield },
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
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            {/* Logo and primary nav */}
            <div className="flex">
              <Link href="/" className="flex items-center px-2 py-2 text-xl font-bold text-primary-700 hover:text-primary-800 transition-colors">
                <Shield className="h-8 w-8 mr-2" />
                JESUS IS KING
              </Link>

              {/* Desktop navigation */}
              <div className="hidden md:ml-6 md:flex md:space-x-8">
                {navigation.map((item) => {
                  const Icon = item.icon
                  return (
                    <Link
                      key={item.name}
                      href={item.href}
                      className={`inline-flex items-center px-1 pt-1 text-sm font-medium ${
                        isActive(item.href)
                          ? 'text-primary-600 border-b-2 border-primary-600'
                          : 'text-gray-500 hover:text-gray-700 hover:border-gray-300 border-b-2 border-transparent'
                      } transition-colors duration-200`}
                    >
                      <Icon className="h-4 w-4 mr-1" />
                      {item.name}
                    </Link>
                  )
                })}
              </div>
            </div>

            {/* Mobile menu button */}
            <div className="md:hidden flex items-center">
              <button
                type="button"
                className="text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-md p-2"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              >
                {mobileMenuOpen ? (
                  <X className="h-6 w-6" />
                ) : (
                  <Menu className="h-6 w-6" />
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="md:hidden">
            <div className="px-2 pt-2 pb-3 space-y-1 bg-white shadow-lg">
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={`flex items-center px-3 py-2 rounded-md text-base font-medium ${
                      isActive(item.href)
                        ? 'text-primary-600 bg-primary-50'
                        : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
                    } transition-colors duration-200`}
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    <Icon className="h-5 w-5 mr-2" />
                    {item.name}
                  </Link>
                )
              })}
            </div>
          </div>
        )}
      </nav>

      {/* Prayer banner (optional) */}
      {showPrayer && (
        <div className="bg-gradient-to-r from-primary-600 to-primary-700 text-white py-2 px-4">
          <div className="max-w-7xl mx-auto text-center text-sm">
            <Heart className="inline h-4 w-4 mr-2" />
&ldquo;Trust in the Lord with all your heart and lean not on your own understanding.&rdquo; - Proverbs 3:5
          </div>
        </div>
      )}

      {/* Main content */}
      <main className="flex-1">
        {children}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-16">
        <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            {/* Brand */}
            <div className="col-span-1 md:col-span-2">
              <Link href="/" className="flex items-center text-xl font-bold text-primary-700 mb-4">
                <Shield className="h-8 w-8 mr-2" />
                JESUS IS KING
              </Link>
              <p className="text-gray-600 max-w-md">
                Secure messaging and document platform designed with faith-based principles.
                All communications protected by end-to-end encryption guided by Biblical wisdom.
              </p>
              <div className="mt-4 scripture-verse text-sm">
&ldquo;He who dwells in the secret place of the Most High shall abide under the shadow of the Almighty.&rdquo; - Psalm 91:1
              </div>
            </div>

            {/* Quick Links */}
            <div>
              <h3 className="text-sm font-semibold text-gray-900 tracking-wider uppercase mb-4">
                Platform
              </h3>
              <ul className="space-y-2">
                <li><Link href="/downloads" className="text-gray-600 hover:text-primary-600">Downloads</Link></li>
                <li><Link href="/safety" className="text-gray-600 hover:text-primary-600">Safety Guide</Link></li>
                <li><Link href="/how-to-use" className="text-gray-600 hover:text-primary-600">How to Use</Link></li>
                <li><Link href="/docs/shuttle_protocol" className="text-gray-600 hover:text-primary-600">Shuttle Protocol</Link></li>
              </ul>
            </div>

            {/* Legal */}
            <div>
              <h3 className="text-sm font-semibold text-gray-900 tracking-wider uppercase mb-4">
                Legal & Faith
              </h3>
              <ul className="space-y-2">
                <li><Link href="/legal" className="text-gray-600 hover:text-primary-600">Legal & Compliance</Link></li>
                <li><Link href="/conduct" className="text-gray-600 hover:text-primary-600">Code of Conduct</Link></li>
                <li><Link href="/scripture" className="text-gray-600 hover:text-primary-600">Scripture</Link></li>
                <li><Link href="/prayer" className="text-gray-600 hover:text-primary-600">Prayer</Link></li>
              </ul>
            </div>
          </div>

          <div className="mt-8 pt-8 border-t border-gray-200">
            <div className="flex flex-col md:flex-row justify-between items-center">
              <p className="text-gray-500 text-sm">
                © 2024 JESUS IS KING Platform. Built for educational purposes. Use responsibly and follow local laws.
              </p>
              <div className="mt-4 md:mt-0">
                <div className="warning text-xs p-2 rounded">
                  <strong>Educational Use Only:</strong> This platform is designed for educational purposes and lawful communication.
                  Users must comply with all applicable laws and regulations.
                </div>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}