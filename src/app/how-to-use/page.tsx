'use client'

import Layout from '../../components/Layout'
import { Info, Download, Shield, Users, Key, Settings, MessageCircle, Book } from 'lucide-react'

export default function HowToUse() {
  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Info className="h-16 w-16 text-blue-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            How to Use
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Complete guide to using the JESUS IS KING secure messaging platform safely and effectively.
            Learn about features, security practices, and getting started.
          </p>
        </div>

        {/* Getting Started */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Download className="h-8 w-8 text-blue-600 mr-3" />
            Getting Started
          </h2>
          <div className="space-y-6">
            {[
              {
                step: 1,
                title: 'Download & Verify',
                description: 'Download the application and verify signatures to ensure authenticity.',
                icon: Download
              },
              {
                step: 2,
                title: 'Install Securely',
                description: 'Install on a secure system, preferably Tails OS or a hardened environment.',
                icon: Shield
              },
              {
                step: 3,
                title: 'Initial Setup',
                description: 'Create your identity, generate keys, and configure security settings.',
                icon: Settings
              },
              {
                step: 4,
                title: 'Connect Safely',
                description: 'Exchange keys out-of-band and establish secure communication channels.',
                icon: Users
              }
            ].map((item) => {
              const Icon = item.icon
              return (
                <div key={item.step} className="card">
                  <div className="flex items-start">
                    <div className="w-12 h-12 bg-blue-600 text-white rounded-full flex items-center justify-center text-lg font-bold mr-4 flex-shrink-0">
                      {item.step}
                    </div>
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-gray-900 mb-2 flex items-center">
                        <Icon className="h-5 w-5 mr-2" />
                        {item.title}
                      </h3>
                      <p className="text-gray-600">{item.description}</p>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </section>

        {/* Key Features */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <MessageCircle className="h-8 w-8 text-blue-600 mr-3" />
            Key Features
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {[
              {
                title: 'End-to-End Encryption',
                description: 'Messages encrypted with Signal protocol for maximum security.',
                icon: Shield
              },
              {
                title: 'Identity Management',
                description: 'Secure identity creation and verification with hardware token support.',
                icon: Key
              },
              {
                title: 'Group Messaging',
                description: 'Secure group communications with perfect forward secrecy.',
                icon: Users
              },
              {
                title: 'Scripture Integration',
                description: 'Built-in access to Scripture for study and inspiration.',
                icon: Book
              }
            ].map((feature, index) => {
              const Icon = feature.icon
              return (
                <div key={index} className="card">
                  <div className="flex items-center mb-4">
                    <Icon className="h-6 w-6 text-blue-600 mr-3" />
                    <h3 className="text-lg font-semibold text-gray-900">{feature.title}</h3>
                  </div>
                  <p className="text-gray-600">{feature.description}</p>
                </div>
              )
            })}
          </div>
        </section>

        {/* Security Best Practices */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Shield className="h-8 w-8 text-blue-600 mr-3" />
            Security Best Practices
          </h2>
          <div className="card">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Before Using</h3>
                <ul className="space-y-2 text-gray-600 text-sm">
                  <li>• Verify download signatures</li>
                  <li>• Use Tails OS or secure environment</li>
                  <li>• Disable swap and enable memory locking</li>
                  <li>• Use hardware kill switches</li>
                  <li>• Disconnect unnecessary peripherals</li>
                </ul>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">During Use</h3>
                <ul className="space-y-2 text-gray-600 text-sm">
                  <li>• Exchange keys out-of-band</li>
                  <li>• Verify recipient fingerprints</li>
                  <li>• Use hardware tokens when possible</li>
                  <li>• Regularly update software</li>
                  <li>• Follow operational security practices</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Troubleshooting */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">Common Issues & Solutions</h2>
          <div className="space-y-4">
            {[
              {
                issue: 'Connection Failed',
                solution: 'Check Tor connectivity and firewall settings. Ensure onion addresses are correct.'
              },
              {
                issue: 'Key Verification Failed',
                solution: 'Re-exchange keys out-of-band. Verify fingerprints match exactly.'
              },
              {
                issue: 'Hardware Token Not Detected',
                solution: 'Check USB connection, install drivers, and verify token compatibility.'
              },
              {
                issue: 'Message Decryption Failed',
                solution: 'Verify sender identity and check for corrupted messages or key mismatches.'
              }
            ].map((item, index) => (
              <div key={index} className="card">
                <h3 className="font-semibold text-gray-900 mb-2">{item.issue}</h3>
                <p className="text-gray-600 text-sm">{item.solution}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Support Resources */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">Support Resources</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Documentation</h3>
              <ul className="space-y-2 text-gray-600">
                <li>• <a href="/safety" className="text-blue-600 hover:underline">Safety & Security Guide</a></li>
                <li>• <a href="/downloads" className="text-blue-600 hover:underline">Download & Verification</a></li>
                <li>• <a href="/conduct" className="text-blue-600 hover:underline">Code of Conduct</a></li>
                <li>• <a href="/legal" className="text-blue-600 hover:underline">Legal & Compliance</a></li>
              </ul>
            </div>
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Community</h3>
              <ul className="space-y-2 text-gray-600">
                <li>• <a href="/prayer" className="text-blue-600 hover:underline">Prayer Requests</a></li>
                <li>• <a href="/scripture" className="text-blue-600 hover:underline">Scripture Study</a></li>
                <li>• Community forums (coming soon)</li>
                <li>• Educational workshops (planned)</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Technical Details */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">Technical Overview</h2>
          <div className="card">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Encryption</h3>
                <ul className="space-y-2 text-gray-600 text-sm">
                  <li>• Signal Protocol for end-to-end encryption</li>
                  <li>• Ed25519 for digital signatures</li>
                  <li>• X25519 for key exchange</li>
                  <li>• ChaCha20-Poly1305 for symmetric encryption</li>
                  <li>• Argon2id for key derivation</li>
                </ul>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Infrastructure</h3>
                <ul className="space-y-2 text-gray-600 text-sm">
                  <li>• Tor hidden services for anonymity</li>
                  <li>• Ephemeral messaging (no permanent storage)</li>
                  <li>• Perfect forward secrecy</li>
                  <li>• Hardware security module support</li>
                  <li>• Cross-platform compatibility</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Scripture & Faith */}
        <section className="card bg-blue-50 border-blue-200 text-center">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">
            Walk in Wisdom
          </h3>
          <div className="scripture-verse text-center">
            "If any of you lacks wisdom, you should ask God, who gives generously to all
            without finding fault, and it will be given to you."
          </div>
          <p className="text-blue-600 font-medium mt-2 mb-4">James 1:5</p>
          <p className="text-gray-600">
            Seek God's wisdom in all your communications. Use these tools responsibly and
            let your digital interactions reflect Christ's love and truth.
          </p>
        </section>
      </div>
    </Layout>
  )
}