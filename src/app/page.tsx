'use client'

import { useState } from 'react'
import Link from 'next/link'
import Layout from '../components/Layout'
import {
  Shield,
  Download,
  Book,
  Heart,
  Eye,
  FileText,
  Users,
  CheckCircle,
  AlertTriangle,
  ArrowRight,
  Play,
  Star,
  Lock,
  Zap,
  Globe
} from 'lucide-react'

export default function Home() {
  const [showPrayer, setShowPrayer] = useState(true)

  const features = [
    {
      icon: Shield,
      title: 'End-to-End Encryption',
      description: 'Military-grade encryption protects every message and document using Signal protocol with advanced session ciphers.',
      color: 'accent'
    },
    {
      icon: FileText,
      title: 'Secure Documents',
      description: 'Create and edit documents with real-time encryption. Export as .securedoc files with tamper-evident signatures.',
      color: 'success'
    },
    {
      icon: Users,
      title: 'Session Ciphers',
      description: 'Create temporary encrypted channels with custom algorithms including classical ciphers for education.',
      color: 'warning'
    },
    {
      icon: Eye,
      title: 'Privacy by Design',
      description: 'No plaintext storage, ephemeral keys, perfect forward secrecy. Server never sees your conversations.',
      color: 'primary'
    },
    {
      icon: Book,
      title: 'Scripture Integration',
      description: 'Built-in access to Scripture with original languages (Hebrew/Greek) for study and meditation.',
      color: 'accent'
    },
    {
      icon: Heart,
      title: 'Faith-Centered',
      description: 'Designed with Biblical principles. Includes prayer features and moral guidance based on Scripture.',
      color: 'success'
    }
  ]

  const benefits = [
    'Verify all download signatures and checksums',
    'Use Tails OS or live USB for sensitive communications',
    'Hardware kill switches for cameras/microphones',
    'Never reuse one-time pad ciphers',
    'Exchange keys out-of-band when possible',
    'Use hardware tokens for authentication'
  ]

  return (
    <Layout>
      {/* Prayer Modal */}
      {showPrayer && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="text-center">
              <div className="w-16 h-16 bg-accent-100 rounded-2xl flex items-center justify-center mx-auto mb-6">
                <Heart className="h-8 w-8 text-accent-600" />
              </div>
              <h3 className="text-xl font-semibold text-primary-900 mb-3">
                Welcome in the Name of Jesus
              </h3>
              <div className="scripture-verse mb-6">
                &ldquo;Trust in the Lord with all your heart and lean not on your own understanding;
                in all your ways submit to him, and he will make your paths straight.&rdquo; - Proverbs 3:5-6
              </div>
              <p className="text-primary-600 text-sm mb-8 leading-relaxed">
                This platform is designed to protect your communications while honoring God.
                Use it responsibly, lawfully, and with wisdom.
              </p>
              <div className="flex gap-3">
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
      <section className="relative overflow-hidden bg-gradient-to-b from-primary-50 to-white">
        <div className="absolute inset-0 bg-dot-pattern opacity-40"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 lg:py-32">
          <div className="text-center">
            <div className="inline-flex items-center px-4 py-2 rounded-full bg-accent-100 text-accent-700 text-sm font-medium mb-8">
              <Star className="h-4 w-4 mr-2" />
              Trusted by faith communities worldwide
            </div>

            <h1 className="text-hero mb-8">
              <span className="gradient-text">JESUS IS KING</span>
              <br />
              <span className="text-primary-700">Secure Messaging</span>
            </h1>

            <p className="text-lead max-w-3xl mx-auto mb-12">
              A secure messaging and document platform designed with Biblical principles.
              Protect your communications with military-grade encryption guided by faith.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-16">
              <Link href="/downloads" className="btn-primary text-base px-8 py-4 hover-scale">
                <Download className="h-5 w-5 mr-2" />
                Download Now
              </Link>
              <Link href="/safety" className="btn-secondary text-base px-8 py-4">
                <Play className="h-5 w-5 mr-2" />
                Watch Demo
              </Link>
            </div>

            {/* Trust indicators */}
            <div className="flex flex-wrap items-center justify-center gap-8 text-sm text-primary-500">
              <div className="flex items-center">
                <Shield className="h-4 w-4 mr-2" />
                End-to-End Encrypted
              </div>
              <div className="flex items-center">
                <Lock className="h-4 w-4 mr-2" />
                Zero-Knowledge Architecture
              </div>
              <div className="flex items-center">
                <Zap className="h-4 w-4 mr-2" />
                Open Source
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Important Legal Notice */}
      <section className="py-6 bg-warning-50 border-y border-warning-200">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="alert-warning">
            <div className="flex items-start">
              <AlertTriangle className="h-5 w-5 mr-3 mt-0.5 flex-shrink-0 text-warning-600" />
              <div>
                <h4 className="font-semibold text-warning-800 mb-2">Educational Use Only - Legal Compliance Required</h4>
                <p className="text-sm text-warning-700 leading-relaxed">
                  This platform is designed for educational purposes and lawful communication only.
                  Users must comply with all applicable laws and regulations. Not intended for illegal activities.
                  <Link href="/legal" className="font-medium hover:underline ml-2">
                    Read full legal disclaimer →
                  </Link>
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-20">
            <h2 className="text-3xl md:text-4xl font-bold text-primary-900 mb-6">
              Secure Communication Guided by Faith
            </h2>
            <p className="text-xl text-primary-600 max-w-3xl mx-auto leading-relaxed">
              Built with Biblical wisdom and cutting-edge cryptography to protect what matters most
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <div key={index} className="feature-card hover-lift">
                  <div className="feature-icon">
                    <Icon className="h-6 w-6" />
                  </div>
                  <h3 className="text-lg font-semibold text-primary-900 mb-3">
                    {feature.title}
                  </h3>
                  <p className="text-primary-600 leading-relaxed">
                    {feature.description}
                  </p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* Safety & Security Section */}
      <section className="py-24 bg-primary-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold text-primary-900 mb-6">
                Safety First - Protect Yourself
              </h2>
              <p className="text-lg text-primary-600 mb-8 leading-relaxed">
                True security requires both strong encryption and operational security.
                Follow our comprehensive safety guide to protect yourself.
              </p>

              <div className="space-y-4 mb-8">
                {benefits.map((benefit, index) => (
                  <div key={index} className="flex items-start">
                    <div className="w-5 h-5 bg-success-100 rounded-full flex items-center justify-center mr-3 mt-0.5">
                      <CheckCircle className="h-3 w-3 text-success-600" />
                    </div>
                    <span className="text-primary-700">{benefit}</span>
                  </div>
                ))}
              </div>

              <Link href="/safety" className="btn-primary">
                Complete Safety Guide
                <ArrowRight className="h-4 w-4 ml-2" />
              </Link>
            </div>

            <div className="card-elevated bg-gradient-to-br from-danger-50 to-warning-50 border-danger-200">
              <div className="text-center">
                <div className="w-16 h-16 bg-danger-100 rounded-2xl flex items-center justify-center mx-auto mb-6">
                  <AlertTriangle className="h-8 w-8 text-danger-600" />
                </div>
                <h3 className="text-xl font-semibold text-danger-800 mb-4">
                  Hardware Safety Warning
                </h3>
                <p className="text-danger-700 mb-6 leading-relaxed">
                  <strong>We strongly advise against destructive hardware modifications.</strong>
                  Instead, use devices with built-in hardware switches or external peripherals.
                </p>
                <div className="bg-danger-100 rounded-xl p-4 text-left mb-6">
                  <h4 className="font-semibold text-danger-800 mb-3">Safe Alternatives:</h4>
                  <ul className="text-sm text-danger-700 space-y-2">
                    <li className="flex items-center">
                      <div className="w-1.5 h-1.5 bg-danger-400 rounded-full mr-2"></div>
                      Devices with hardware kill switches (Purism Librem)
                    </li>
                    <li className="flex items-center">
                      <div className="w-1.5 h-1.5 bg-danger-400 rounded-full mr-2"></div>
                      External webcam/microphone (disconnect when not needed)
                    </li>
                    <li className="flex items-center">
                      <div className="w-1.5 h-1.5 bg-danger-400 rounded-full mr-2"></div>
                      Faraday bags for radio isolation
                    </li>
                    <li className="flex items-center">
                      <div className="w-1.5 h-1.5 bg-danger-400 rounded-full mr-2"></div>
                      Live USB/Tails OS for non-persistent usage
                    </li>
                  </ul>
                </div>
                <Link href="/safety" className="btn btn-secondary bg-danger-600 text-white hover:bg-danger-700 border-0">
                  Read Full Safety Guide
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Scripture & Faith Section */}
      <section className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <div className="w-16 h-16 bg-accent-100 rounded-2xl flex items-center justify-center mx-auto mb-8">
            <Book className="h-8 w-8 text-accent-600" />
          </div>
          <h2 className="text-3xl md:text-4xl font-bold text-primary-900 mb-6">
            Founded on Scripture
          </h2>
          <div className="scripture-verse max-w-4xl mx-auto mb-8">
            &ldquo;He who dwells in the secret place of the Most High shall abide under the shadow of the Almighty.
            I will say of the Lord, &lsquo;He is my refuge and my fortress; my God, in Him I will trust.&rsquo;&rdquo; - Psalm 91:1-2
          </div>
          <p className="text-lg text-primary-600 max-w-3xl mx-auto mb-12 leading-relaxed">
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
            <Link href="/conduct" className="btn-ghost">
              <Shield className="h-4 w-4 mr-2" />
              Code of Conduct
            </Link>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 bg-gradient-to-r from-accent-600 to-accent-700">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
            Ready to Secure Your Communications?
          </h2>
          <p className="text-xl text-accent-100 mb-12 leading-relaxed">
            Join thousands who trust JESUS IS KING for their secure messaging needs.
            Download now and experience true privacy.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link href="/downloads" className="btn bg-white text-accent-600 hover:bg-accent-50">
              <Download className="h-5 w-5 mr-2" />
              Download for Free
            </Link>
            <Link href="/safety" className="btn border-2 border-white text-white hover:bg-white hover:text-accent-600">
              <Globe className="h-5 w-5 mr-2" />
              View Documentation
            </Link>
          </div>
        </div>
      </section>
    </Layout>
  )
}