import { useState } from 'react'
import Layout from '../components/Layout'
import Link from 'next/link'
import {
  Shield,
  Download,
  Book,
  Heart,
  Lock,
  Eye,
  FileText,
  Users,
  CheckCircle,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  Scale
} from 'lucide-react'

export default function Home() {
  const [showPrayer, setShowPrayer] = useState(true)

  const features = [
    {
      icon: Shield,
      title: 'End-to-End Encryption',
      description: 'Military-grade encryption protects every message and document. Based on Signal protocol with additional session ciphers.'
    },
    {
      icon: FileText,
      title: 'Secure Documents',
      description: 'Create and edit documents with real-time encryption. Export as .securedoc files with tamper-evident signatures.'
    },
    {
      icon: Users,
      title: 'Session Ciphers',
      description: 'Create temporary encrypted channels with custom algorithms including classical ciphers for education.'
    },
    {
      icon: Eye,
      title: 'Privacy by Design',
      description: 'No plaintext storage, ephemeral keys, perfect forward secrecy. Server never sees your conversations.'
    },
    {
      icon: Book,
      title: 'Scripture Integration',
      description: 'Built-in access to Scripture with original languages (Hebrew/Greek) for study and meditation.'
    },
    {
      icon: Heart,
      title: 'Faith-Centered',
      description: 'Designed with Biblical principles. Includes prayer features and moral guidance based on Scripture.'
    }
  ]

  const safetyChecklist = [
    'Verify all download signatures and checksums',
    'Use Tails OS or live USB for sensitive communications',
    'Hardware kill switches for cameras/microphones',
    'Never reuse one-time pad ciphers',
    'Exchange keys out-of-band when possible',
    'Use hardware tokens for authentication'
  ]

  return (
    <Layout showPrayer={showPrayer}>
      {/* Prayer Modal */}
      {showPrayer && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div className="prayer-card max-w-md w-full">
            <div className="text-center">
              <Heart className="h-12 w-12 text-primary-600 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                Welcome in the Name of Jesus
              </h3>
              <div className="scripture-verse text-sm mb-4">
                "Trust in the Lord with all your heart and lean not on your own understanding;
                in all your ways submit to him, and he will make your paths straight." - Proverbs 3:5-6
              </div>
              <p className="text-gray-600 text-sm mb-6">
                This platform is designed to protect your communications while honoring God.
                Use it responsibly, lawfully, and with wisdom.
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowPrayer(false)}
                  className="btn-primary flex-1"
                >
                  Continue with Prayer
                </button>
                <Link href="/prayer" className="btn-outline">
                  Submit Prayer
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Hero Section */}
      <section className="hero-gradient text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="hero-title font-bold mb-6 text-balance text-glow scale-in">
            JESUS IS KING
          </h1>
          <p className="text-xl md:text-2xl mb-8 text-primary-100 max-w-3xl mx-auto text-balance">
            Secure messaging and document platform designed with Biblical principles.
            Protect your communications with military-grade encryption guided by faith.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-12">
            <Link href="/downloads" className="btn-enhanced bg-white text-primary-700 hover:bg-gray-100 px-8 py-3 text-lg glow">
              <Download className="h-5 w-5 mr-2" />
              Download Now
            </Link>
            <Link href="/safety" className="btn-enhanced border-2 border-white text-white hover:bg-white hover:text-primary-700 px-8 py-3 text-lg">
              <Shield className="h-5 w-5 mr-2" />
              Safety Guide
            </Link>
          </div>

          {/* Important Legal Notice */}
          <div className="danger max-w-2xl mx-auto text-left">
            <div className="flex items-start">
              <AlertTriangle className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0 text-red-600" />
              <div>
                <strong className="block mb-1 text-black">Educational Use Only - Legal Compliance Required</strong>
                <p className="text-sm text-black">
                  This platform is designed for educational purposes and lawful communication only.
                  Users must comply with all applicable laws and regulations. Not intended for illegal activities.
                  <Link href="/legal" className="text-blue-600 hover:underline ml-1">
                    Read full legal disclaimer →
                  </Link>
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-gray-900 mb-4">
              Secure Communication Guided by Faith
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Built with Biblical wisdom and cutting-edge cryptography to protect what matters most.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <div key={index} className="card-enhanced text-center fade-in floating" style={{animationDelay: `${index * 0.2}s`}}>
                  <div className="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center mx-auto mb-4 pulse-green">
                    <Icon className="h-6 w-6 text-primary-600" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2 gradient-text">
                    {feature.title}
                  </h3>
                  <p className="text-gray-600">
                    {feature.description}
                  </p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* Safety & Security Section */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl font-bold text-gray-900 mb-6">
                Safety First - Protect Yourself
              </h2>
              <p className="text-lg text-gray-600 mb-8">
                True security requires both strong encryption and operational security.
                Follow our comprehensive safety guide to protect yourself.
              </p>

              <div className="space-y-3">
                {safetyChecklist.map((item, index) => (
                  <div key={index} className="flex items-start">
                    <CheckCircle className="h-5 w-5 text-green-500 mr-3 mt-0.5 flex-shrink-0" />
                    <span className="text-gray-700">{item}</span>
                  </div>
                ))}
              </div>

              <div className="mt-8">
                <Link href="/safety" className="btn-primary inline-flex items-center">
                  Complete Safety Guide
                  <ChevronRight className="h-4 w-4 ml-2" />
                </Link>
              </div>
            </div>

            <div className="card bg-gradient-to-br from-red-50 to-orange-50 border-red-200">
              <div className="text-center">
                <AlertTriangle className="h-12 w-12 text-red-600 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-red-800 mb-4">
                  Hardware Safety Warning
                </h3>
                <p className="text-red-700 mb-4">
                  <strong>We strongly advise against destructive hardware modifications.</strong>
                  Instead, use devices with built-in hardware switches or external peripherals that can be safely disconnected.
                </p>
                <div className="bg-red-100 rounded-lg p-4 text-left">
                  <h4 className="font-semibold text-red-800 mb-2">Safe Alternatives:</h4>
                  <ul className="text-sm text-red-700 space-y-1">
                    <li>• Devices with hardware kill switches (Purism Librem)</li>
                    <li>• External webcam/microphone (disconnect when not needed)</li>
                    <li>• Faraday bags for radio isolation</li>
                    <li>• Live USB/Tails OS for non-persistent usage</li>
                  </ul>
                </div>
                <Link href="/safety" className="btn bg-red-600 text-white hover:bg-red-700 mt-4">
                  Read Full Safety Guide
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Scripture & Faith Section */}
      <section className="py-20 bg-gradient-to-br from-primary-50 to-secondary-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <Book className="h-16 w-16 text-primary-600 mx-auto mb-6" />
          <h2 className="text-3xl font-bold text-gray-900 mb-6">
            Founded on Scripture
          </h2>
          <div className="scripture-verse text-lg max-w-3xl mx-auto mb-8">
            "He who dwells in the secret place of the Most High shall abide under the shadow of the Almighty.
            I will say of the Lord, 'He is my refuge and my fortress; my God, in Him I will trust.'" - Psalm 91:1-2
          </div>
          <p className="text-lg text-gray-600 max-w-3xl mx-auto mb-8">
            This platform is built with Biblical principles at its core. Access Scripture in original languages,
            submit prayers, and follow our faith-based code of conduct.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link href="/scripture" className="btn-primary">
              <Book className="h-4 w-4 mr-2" />
              Read Scripture
            </Link>
            <Link href="/prayer" className="btn-outline">
              <Heart className="h-4 w-4 mr-2" />
              Submit Prayer
            </Link>
            <Link href="/conduct" className="btn-outline">
              <Scale className="h-4 w-4 mr-2" />
              Code of Conduct
            </Link>
          </div>
        </div>
      </section>

      {/* Quick Start */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-900 mb-4">
              Get Started Securely
            </h2>
            <p className="text-lg text-gray-600">
              Follow these steps to begin secure communication
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="card text-center">
              <div className="w-10 h-10 bg-primary-600 text-white rounded-full flex items-center justify-center mx-auto mb-4 text-lg font-bold">
                1
              </div>
              <h3 className="text-lg font-semibold mb-2">Download & Verify</h3>
              <p className="text-gray-600 mb-4">Download the application and verify signatures to ensure authenticity.</p>
              <Link href="/downloads" className="text-primary-600 hover:underline inline-flex items-center">
                Download Page <ExternalLink className="h-4 w-4 ml-1" />
              </Link>
            </div>

            <div className="card text-center">
              <div className="w-10 h-10 bg-primary-600 text-white rounded-full flex items-center justify-center mx-auto mb-4 text-lg font-bold">
                2
              </div>
              <h3 className="text-lg font-semibold mb-2">Setup Safely</h3>
              <p className="text-gray-600 mb-4">Follow our safety guide for secure installation and operational security.</p>
              <Link href="/safety" className="text-primary-600 hover:underline inline-flex items-center">
                Safety Guide <ExternalLink className="h-4 w-4 ml-1" />
              </Link>
            </div>

            <div className="card text-center">
              <div className="w-10 h-10 bg-primary-600 text-white rounded-full flex items-center justify-center mx-auto mb-4 text-lg font-bold">
                3
              </div>
              <h3 className="text-lg font-semibold mb-2">Use Responsibly</h3>
              <p className="text-gray-600 mb-4">Follow our code of conduct and use the platform for lawful purposes.</p>
              <Link href="/how-to-use" className="text-primary-600 hover:underline inline-flex items-center">
                Usage Guide <ExternalLink className="h-4 w-4 ml-1" />
              </Link>
            </div>
          </div>
        </div>
      </section>
    </Layout>
  )
}