'use client'

import Layout from '../../components/Layout'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Download,
  Eye,
  Wifi,
  HardDrive,
  Usb,
  Info
} from 'lucide-react'

export default function Safety() {
  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Shield className="h-16 w-16 text-blue-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Safety & Operational Security Guide
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Protecting your communications requires both strong encryption and proper operational security.
            Follow this guide to stay safe while using the JESUS IS KING platform.
          </p>
        </div>

        {/* Critical Warning */}
        <div className="alert-danger mb-12">
          <div className="flex items-start">
            <AlertTriangle className="h-6 w-6 mr-3 mt-1 flex-shrink-0" />
            <div>
              <h3 className="text-lg font-semibold mb-2">⚠️ IMPORTANT SAFETY WARNING</h3>
              <p className="mb-4">
                <strong>We strongly advise AGAINST destructive hardware modifications</strong> such as unsoldering
                microphones, cameras, or removing hard drives. These modifications can damage your device,
                void warranties, and create safety hazards.
              </p>
              <p>
                Instead, we provide <strong>safe, legal, and non-destructive alternatives</strong> that offer
                equivalent or better security without damaging your equipment.
              </p>
            </div>
          </div>
        </div>

        {/* Safe Alternatives Section */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <CheckCircle className="h-8 w-8 text-green-600 mr-3" />
            Safe & Legal Privacy Protection Methods
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {/* Hardware Kill Switches */}
            <div className="card">
              <div className="flex items-center mb-4">
                <Eye className="h-6 w-6 text-blue-600 mr-3" />
                <h3 className="text-lg font-semibold">Hardware Kill Switches</h3>
              </div>
              <p className="text-gray-600 mb-4">
                Use laptops with built-in hardware kill switches for cameras and microphones.
              </p>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• <strong>Purism Librem</strong> laptops (hardware switches)</li>
                <li>• <strong>Framework</strong> laptops (modular camera/mic)</li>
                <li>• <strong>ThinkPad</strong> models with camera covers</li>
                <li>• Physical camera covers/lens caps</li>
              </ul>
            </div>

            {/* External Peripherals */}
            <div className="card">
              <div className="flex items-center mb-4">
                <Usb className="h-6 w-6 text-blue-600 mr-3" />
                <h3 className="text-lg font-semibold">External Peripherals</h3>
              </div>
              <p className="text-gray-600 mb-4">
                Use external devices that can be safely disconnected when not needed.
              </p>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• External USB webcam (unplug when not in use)</li>
                <li>• External USB microphone (physical disconnect)</li>
                <li>• USB audio interface with mute switches</li>
                <li>• External speakers instead of built-in audio</li>
              </ul>
            </div>

            {/* Live USB/Tails */}
            <div className="card">
              <div className="flex items-center mb-4">
                <HardDrive className="h-6 w-6 text-blue-600 mr-3" />
                <h3 className="text-lg font-semibold">Live USB & Tails OS</h3>
              </div>
              <p className="text-gray-600 mb-4">
                Use a live, non-persistent operating system for sensitive communications.
              </p>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• <strong>Tails OS</strong> (The Amnesic Incognito Live System)</li>
                <li>• Boot from external USB drive</li>
                <li>• No persistent storage on host machine</li>
                <li>• Built-in Tor and encryption tools</li>
              </ul>
            </div>

            {/* Faraday Bags */}
            <div className="card">
              <div className="flex items-center mb-4">
                <Wifi className="h-6 w-6 text-blue-600 mr-3" />
                <h3 className="text-lg font-semibold">Radio Isolation</h3>
              </div>
              <p className="text-gray-600 mb-4">
                Block electromagnetic signals when maximum privacy is needed.
              </p>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• <strong>Faraday bags</strong> for phones and devices</li>
                <li>• RF-blocking pouches for key fobs</li>
                <li>• Airplane mode + physical isolation</li>
                <li>• Remove batteries when possible</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Tails OS Setup Guide */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Download className="h-8 w-8 text-blue-600 mr-3" />
            Tails OS Setup Guide
          </h2>

          <div className="card bg-blue-50 border-blue-200 mb-6">
            <div className="flex items-start">
              <Info className="h-5 w-5 text-blue-600 mr-3 mt-0.5" />
              <div>
                <h4 className="font-semibold text-blue-800">What is Tails?</h4>
                <p className="text-blue-700 text-sm mt-1">
                  Tails is a live operating system that you can start on almost any computer from a USB stick.
                  It preserves your privacy and anonymity by leaving no traces and using Tor for all internet connections.
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm mr-3">1</span>
                Download Tails Safely
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Always download Tails from the official website and verify the download.
                </p>
                <div className="bg-gray-100 p-4 rounded-lg mb-4">
                  <p className="text-sm font-mono">
                    Official Site: <a href="https://tails.boum.org" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">https://tails.boum.org</a>
                  </p>
                </div>
                <div className="alert-warning">
                  <p className="text-sm">
                    <strong>Always verify the cryptographic signature</strong> to ensure the download hasn't been tampered with.
                    Follow the verification instructions on the official Tails website.
                  </p>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm mr-3">2</span>
                Verify Download Integrity
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Verification ensures your download is authentic and hasn't been modified.
                </p>
                <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono mb-4">
                  <div className="mb-2"># Download Tails signing key</div>
                  <div className="mb-2">curl -s https://tails.boum.org/tails-signing.key | gpg --import</div>
                  <div className="mb-2"># Verify the signature</div>
                  <div>gpg --verify tails-amd64-*.img.sig tails-amd64-*.img</div>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <p className="text-sm text-green-700">
                    Look for "Good signature from 'Tails developers'" in the verification output.
                  </p>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm mr-3">3</span>
                Create Bootable USB
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Create a bootable Tails USB drive using the verified image.
                </p>
                <ul className="text-sm text-gray-600 space-y-2 mb-4">
                  <li>• Use at least 8GB USB drive</li>
                  <li>• Use Tails Installer or dd command</li>
                  <li>• Backup any existing data (will be erased)</li>
                  <li>• Test the USB before sensitive use</li>
                </ul>
                <div className="alert-info">
                  <p className="text-sm">
                    <strong>Recommended:</strong> Create two Tails USBs - one for testing and one for actual use.
                  </p>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm mr-3">4</span>
                Boot Safely
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Boot from the Tails USB and configure for maximum security.
                </p>
                <ul className="text-sm text-gray-600 space-y-2">
                  <li>• Disable WiFi/Ethernet during boot if needed</li>
                  <li>• Set BIOS/UEFI to boot from USB first</li>
                  <li>• Consider disabling internal hard drives in BIOS</li>
                  <li>• Use Tails with offline mode for document work</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Security Checklist */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Complete Security Checklist
          </h2>

          <div className="space-y-4">
            {[
              'Use devices with hardware kill switches for cameras/microphones',
              'Boot from Tails USB for sensitive communications',
              'Verify all software downloads with GPG signatures and checksums',
              'Use external peripherals that can be physically disconnected',
              'Store sensitive data on encrypted external drives only',
              'Use Faraday bags for radio isolation when needed',
              'Exchange encryption keys out-of-band (in person when possible)',
              'Never reuse one-time pad ciphers',
              'Use hardware tokens for two-factor authentication',
              'Keep software updated with verified updates only',
              'Use onion services (.onion addresses) when available',
              'Practice good physical security (lock screens, secure locations)',
              'Consult legal counsel in sensitive jurisdictions',
              'Follow local laws and regulations',
              'Use the platform for lawful purposes only'
            ].map((item, index) => (
              <div key={index} className="flex items-start">
                <CheckCircle className="h-5 w-5 text-green-500 mr-3 mt-0.5 flex-shrink-0" />
                <span className="text-gray-700">{item}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Scripture & Faith */}
        <section className="card bg-blue-50 border-blue-200 text-center">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">
            Wisdom from Scripture
          </h3>
          <div className="scripture-verse text-center">
            "The simple believe anything, but the prudent give thought to their steps." - Proverbs 14:15
          </div>
          <p className="text-gray-600 mt-4">
            God calls us to be wise and careful. Use these security practices as part of faithful stewardship
            of the tools and communications He has entrusted to you.
          </p>
        </section>
      </div>
    </Layout>
  )
}