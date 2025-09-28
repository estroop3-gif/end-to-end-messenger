import Layout from '../components/Layout'
import Link from 'next/link'
import {
  Info,
  Download,
  Shield,
  Key,
  Users,
  FileText,
  Settings,
  CheckCircle,
  AlertTriangle,
  Book,
  ExternalLink,
  Play,
  Pause,
  RotateCcw
} from 'lucide-react'

export default function HowToUse() {
  const setupSteps = [
    {
      title: 'Download & Install',
      description: 'Download the application and verify its authenticity',
      details: [
        'Visit the downloads page and select your platform',
        'Verify GPG signature and SHA256 checksum',
        'Install following your operating system guidelines',
        'Run initial setup wizard'
      ],
      icon: Download,
      link: '/downloads'
    },
    {
      title: 'Security Setup',
      description: 'Configure encryption keys and security preferences',
      details: [
        'Generate new encryption keypair or import existing',
        'Set up strong local authentication passphrase',
        'Configure hardware security keys if available',
        'Review and adjust privacy settings'
      ],
      icon: Key,
      link: '/safety'
    },
    {
      title: 'Connection Setup',
      description: 'Connect to the message shuttle service',
      details: [
        'Configure connection to shuttle server',
        'Verify server certificate and identity',
        'Test connection and encryption handshake',
        'Set up backup connection methods'
      ],
      icon: Shield,
      link: null
    },
    {
      title: 'Contact Exchange',
      description: 'Safely exchange contact information with others',
      details: [
        'Exchange public keys out-of-band when possible',
        'Verify key fingerprints through alternative channels',
        'Use QR codes for in-person key exchange',
        'Maintain contact verification records'
      ],
      icon: Users,
      link: null
    }
  ]

  const features = [
    {
      title: 'Secure Messaging',
      description: 'End-to-end encrypted text messaging with perfect forward secrecy',
      instructions: [
        'Select contact from verified contacts list',
        'Type your message in the secure input field',
        'Message is automatically encrypted before sending',
        'Recipient receives and decrypts message locally',
        'Message keys are rotated for forward secrecy'
      ],
      icon: Users
    },
    {
      title: 'Document Creation',
      description: 'Create and share encrypted documents with tamper-evident signatures',
      instructions: [
        'Open document editor from main menu',
        'Write content using rich text features',
        'Document is encrypted in real-time',
        'Save as .securedoc format with digital signature',
        'Share with contacts or export for external storage'
      ],
      icon: FileText
    },
    {
      title: 'Session Ciphers',
      description: 'Create temporary encrypted channels with custom algorithms',
      instructions: [
        'Create new session cipher from Ciphers menu',
        'Choose cipher type (modern, classical, or custom)',
        'Generate session key or import shared key',
        'Invite participants to encrypted session',
        'All session data destroyed after timeout'
      ],
      icon: Settings
    }
  ]

  const securityTips = [
    {
      category: 'Authentication',
      tips: [
        'Use a unique, strong passphrase for local authentication',
        'Enable hardware security keys if supported',
        'Never share your private keys or passphrases',
        'Use two-factor authentication when available'
      ]
    },
    {
      category: 'Communication Security',
      tips: [
        'Always verify contact identity before sensitive conversations',
        'Use out-of-band verification for new contacts',
        'Be cautious of social engineering attempts',
        'Regularly rotate encryption keys'
      ]
    },
    {
      category: 'Operational Security',
      tips: [
        'Use secure devices and networks when possible',
        'Keep software updated and verify all updates',
        'Use Tails OS for maximum anonymity',
        'Practice good physical security'
      ]
    }
  ]

  return (
    <Layout
      title="How to Use"
      description="Complete guide to using the JESUS IS KING secure messaging platform"
    >
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Info className="h-16 w-16 text-primary-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            How to Use the Platform
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Complete guide to secure communication using the JESUS IS KING platform.
            Follow these steps to protect your conversations with faith and wisdom.
          </p>
        </div>

        {/* Scripture */}
        <div className="prayer-card text-center mb-12">
          <div className="scripture-verse">
            "Commit to the Lord whatever you do, and he will establish your plans." - Proverbs 16:3
          </div>
        </div>

        {/* Quick Start Checklist */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Quick Start Checklist
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {setupSteps.map((step, index) => {
              const Icon = step.icon
              return (
                <div key={index} className="card">
                  <div className="flex items-start mb-4">
                    <div className="w-10 h-10 bg-primary-600 text-white rounded-full flex items-center justify-center text-lg font-bold mr-4 mt-1">
                      {index + 1}
                    </div>
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-gray-900 mb-2 flex items-center">
                        <Icon className="h-5 w-5 text-primary-600 mr-2" />
                        {step.title}
                      </h3>
                      <p className="text-gray-600 mb-4">{step.description}</p>
                    </div>
                  </div>

                  <ul className="text-sm text-gray-600 space-y-2 ml-14">
                    {step.details.map((detail, detailIndex) => (
                      <li key={detailIndex} className="flex items-start">
                        <CheckCircle className="h-4 w-4 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                        {detail}
                      </li>
                    ))}
                  </ul>

                  {step.link && (
                    <div className="mt-4 ml-14">
                      <Link href={step.link} className="text-primary-600 hover:underline text-sm flex items-center">
                        Learn more <ExternalLink className="h-3 w-3 ml-1" />
                      </Link>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </section>

        {/* Feature Guides */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Feature Guides
          </h2>

          <div className="space-y-8">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <div key={index} className="card">
                  <div className="flex items-center mb-6">
                    <Icon className="h-8 w-8 text-primary-600 mr-3" />
                    <div>
                      <h3 className="text-xl font-semibold text-gray-900">{feature.title}</h3>
                      <p className="text-gray-600">{feature.description}</p>
                    </div>
                  </div>

                  <div className="ml-11">
                    <h4 className="font-semibold text-gray-900 mb-3">Step-by-step instructions:</h4>
                    <ol className="space-y-2">
                      {feature.instructions.map((instruction, instructionIndex) => (
                        <li key={instructionIndex} className="flex items-start">
                          <span className="w-6 h-6 bg-primary-100 text-primary-700 rounded-full flex items-center justify-center text-sm font-medium mr-3 mt-0.5 flex-shrink-0">
                            {instructionIndex + 1}
                          </span>
                          <span className="text-gray-700 text-sm">{instruction}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                </div>
              )
            })}
          </div>
        </section>

        {/* Security Best Practices */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Shield className="h-8 w-8 text-primary-600 mr-3" />
            Security Best Practices
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {securityTips.map((category, index) => (
              <div key={index} className="card">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  {category.category}
                </h3>
                <ul className="space-y-3">
                  {category.tips.map((tip, tipIndex) => (
                    <li key={tipIndex} className="flex items-start">
                      <Shield className="h-4 w-4 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-700 text-sm">{tip}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>

        {/* Common Issues & Troubleshooting */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Common Issues & Troubleshooting
          </h2>

          <div className="space-y-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Connection Issues
              </h3>
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Cannot connect to shuttle server</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Check internet connection and firewall settings</li>
                    <li>• Verify server address and port configuration</li>
                    <li>• Try alternative connection methods (Tor, VPN)</li>
                    <li>• Check server status and availability</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Encryption handshake fails</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Verify server certificate and fingerprint</li>
                    <li>• Check system clock synchronization</li>
                    <li>• Update to latest application version</li>
                    <li>• Regenerate encryption keys if corrupted</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Message Delivery Issues
              </h3>
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Messages not being delivered</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Verify recipient's online status and connection</li>
                    <li>• Check message queue and retry failed sends</li>
                    <li>• Confirm contact's public key is current</li>
                    <li>• Test with a simple text message first</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Cannot decrypt received messages</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Verify your private key is accessible</li>
                    <li>• Check if sender used correct public key</li>
                    <li>• Re-exchange keys with sender if necessary</li>
                    <li>• Look for key rotation notifications</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Authentication Problems
              </h3>
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Forgot local passphrase</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Try passphrase variations and common patterns</li>
                    <li>• Use passphrase recovery if configured</li>
                    <li>• Restore from secure backup if available</li>
                    <li>• As last resort, reset and lose encrypted data</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Hardware key not recognized</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Check USB connection and device status</li>
                    <li>• Install latest device drivers</li>
                    <li>• Test hardware key with other applications</li>
                    <li>• Use backup authentication method temporarily</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Advanced Features */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Advanced Features
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Custom Cipher Implementation
              </h3>
              <p className="text-gray-600 mb-4 text-sm">
                Create your own encryption algorithms for educational purposes.
              </p>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Design classical ciphers (Caesar, Vigenère, etc.)</li>
                <li>• Implement modern stream ciphers</li>
                <li>• Test cipher strength and security</li>
                <li>• Share educational implementations</li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Scriptural Integration
              </h3>
              <p className="text-gray-600 mb-4 text-sm">
                Incorporate Scripture into your secure communications.
              </p>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Access Bible verses in multiple translations</li>
                <li>• Study original Hebrew and Greek texts</li>
                <li>• Include daily verses in messages</li>
                <li>• Create prayer groups and Bible studies</li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Anonymity Features
              </h3>
              <p className="text-gray-600 mb-4 text-sm">
                Enhanced privacy and anonymity options.
              </p>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Route through Tor onion services</li>
                <li>• Use temporary identity keys</li>
                <li>• Anonymous group messaging</li>
                <li>• Metadata scrubbing and timing analysis protection</li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Document Security
              </h3>
              <p className="text-gray-600 mb-4 text-sm">
                Advanced document protection and verification.
              </p>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Tamper-evident digital signatures</li>
                <li>• Time-stamped document versions</li>
                <li>• Collaborative editing with conflict resolution</li>
                <li>• Export to standard encrypted formats</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Safety Reminders */}
        <section className="mb-16">
          <div className="danger">
            <div className="flex items-start">
              <AlertTriangle className="h-6 w-6 mr-3 mt-1 flex-shrink-0" />
              <div>
                <h3 className="text-lg font-semibold mb-2">⚠️ IMPORTANT SAFETY REMINDERS</h3>
                <ul className="space-y-2 text-sm">
                  <li>• This platform is for educational and lawful communication only</li>
                  <li>• Always comply with applicable laws and regulations</li>
                  <li>• Never use for illegal activities or to harm others</li>
                  <li>• Report suspected illegal activity to authorities</li>
                  <li>• Follow our <Link href="/conduct" className="text-red-800 underline">code of conduct</Link> and <Link href="/safety" className="text-red-800 underline">safety guidelines</Link></li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Additional Resources */}
        <section>
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Additional Resources
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Platform Documentation</h3>
              <ul className="space-y-2">
                <li><Link href="/safety" className="text-primary-600 hover:underline">Safety & Operational Security</Link></li>
                <li><Link href="/downloads" className="text-primary-600 hover:underline">Downloads & Verification</Link></li>
                <li><Link href="/conduct" className="text-primary-600 hover:underline">Code of Conduct</Link></li>
                <li><Link href="/legal" className="text-primary-600 hover:underline">Legal Terms & Compliance</Link></li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Faith & Scripture</h3>
              <ul className="space-y-2">
                <li><Link href="/scripture" className="text-primary-600 hover:underline">Scripture Reading & Study</Link></li>
                <li><Link href="/prayer" className="text-primary-600 hover:underline">Prayer Submission</Link></li>
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">Daily Devotionals <ExternalLink className="h-3 w-3 ml-1" /></a></li>
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">Christian Security Ethics <ExternalLink className="h-3 w-3 ml-1" /></a></li>
              </ul>
            </div>
          </div>

          <div className="prayer-card text-center mt-8">
            <Book className="h-8 w-8 text-primary-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-900 mb-4">
              Wisdom from Scripture
            </h3>
            <div className="scripture-verse text-center">
              "Plans fail for lack of counsel, but with many advisers they succeed." - Proverbs 15:22
            </div>
            <p className="text-gray-600 mt-4">
              When in doubt, seek counsel from wise and godly people. Don't hesitate to ask for help
              with security practices or platform usage.
            </p>
          </div>
        </section>
      </div>
    </Layout>
  )
}