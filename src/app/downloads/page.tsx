'use client'

import Link from 'next/link'
import Layout from '../../components/Layout'
import {
  Download,
  Shield,
  CheckCircle,
  AlertTriangle,
  Key,
  FileCheck,
  ExternalLink,
  Copy,
  Eye,
  Lock
} from 'lucide-react'

export default function Downloads() {
  const downloads = [
    {
      platform: 'Windows',
      version: '1.0.0',
      size: '45.2 MB',
      file: 'jesus-is-king-windows-x64-1.0.0.exe',
      sha256: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
      signature: 'jesus-is-king-windows-x64-1.0.0.exe.sig',
      download_url: '#'
    },
    {
      platform: 'macOS',
      version: '1.0.0',
      size: '52.1 MB',
      file: 'jesus-is-king-macos-universal-1.0.0.dmg',
      sha256: 'b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567a',
      signature: 'jesus-is-king-macos-universal-1.0.0.dmg.sig',
      download_url: '#'
    },
    {
      platform: 'Linux',
      version: '1.0.0',
      size: '48.7 MB',
      file: 'jesus-is-king-linux-x64-1.0.0.AppImage',
      sha256: 'c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2',
      signature: 'jesus-is-king-linux-x64-1.0.0.AppImage.sig',
      download_url: '#'
    }
  ]

  const publicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGXXXXXXBEAC1234567890abcdef...
[Full GPG public key would be here]
...567890abcdef1234567890abcdef=
=XXXX
-----END PGP PUBLIC KEY BLOCK-----`

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Download className="h-16 w-16 text-blue-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Downloads & Verification
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Download the secure messaging platform and always verify signatures to ensure authenticity.
            Never skip verification - your security depends on it.
          </p>
        </div>

        {/* Critical Warning */}
        <div className="alert-danger mb-12">
          <div className="flex items-start">
            <AlertTriangle className="h-6 w-6 mr-3 mt-1 flex-shrink-0" />
            <div>
              <h3 className="text-lg font-semibold mb-2">⚠️ VERIFICATION REQUIRED</h3>
              <p className="mb-4">
                <strong>Always verify downloads before installation.</strong> Failure to verify signatures
                could result in installing compromised software. This is a critical security step.
              </p>
              <p>
                Follow the verification steps below exactly as written. When in doubt, ask for help
                rather than skipping verification.
              </p>
            </div>
          </div>
        </div>

        {/* Downloads Section */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Download className="h-8 w-8 text-blue-600 mr-3" />
            Available Downloads
          </h2>

          <div className="space-y-6">
            {downloads.map((download, index) => (
              <div key={index} className="card">
                <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
                  <div className="mb-4 lg:mb-0">
                    <h3 className="text-lg font-semibold text-gray-900 mb-2">
                      {download.platform} v{download.version}
                    </h3>
                    <p className="text-gray-600 mb-2">
                      File: <code className="text-sm bg-gray-100 px-2 py-1 rounded">{download.file}</code>
                    </p>
                    <p className="text-gray-600">
                      Size: {download.size}
                    </p>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-3">
                    <a
                      href={download.download_url}
                      className="btn-primary inline-flex items-center justify-center"
                      download
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download
                    </a>
                    <a
                      href={download.download_url + '.sig'}
                      className="btn-outline inline-flex items-center justify-center"
                      download
                    >
                      <Key className="h-4 w-4 mr-2" />
                      Signature
                    </a>
                  </div>
                </div>

                {/* Checksum */}
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm font-medium text-gray-700">SHA256 Checksum:</label>
                    <button
                      onClick={() => copyToClipboard(download.sha256)}
                      className="text-blue-600 hover:text-blue-700 p-1"
                      title="Copy to clipboard"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="bg-gray-100 p-3 rounded font-mono text-xs break-all">
                    {download.sha256}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* GPG Public Key */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Key className="h-8 w-8 text-blue-600 mr-3" />
            GPG Public Key
          </h2>

          <div className="card">
            <div className="mb-4">
              <h3 className="text-lg font-semibold mb-2">JESUS IS KING Signing Key</h3>
              <p className="text-gray-600 mb-4">
                Import this public key to verify download signatures. Save this key securely for future use.
              </p>
            </div>

            <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono overflow-x-auto mb-4">
              <pre>{publicKey}</pre>
            </div>

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={() => copyToClipboard(publicKey)}
                className="btn-outline inline-flex items-center justify-center"
              >
                <Copy className="h-4 w-4 mr-2" />
                Copy Public Key
              </button>
              <a
                href="#"
                className="btn-outline inline-flex items-center justify-center"
                download
              >
                <Download className="h-4 w-4 mr-2" />
                Download Key File
              </a>
            </div>

            <div className="alert-info mt-4">
              <p className="text-sm">
                <strong>Key Fingerprint:</strong> 1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678
              </p>
            </div>
          </div>
        </section>

        {/* Verification Guide */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <FileCheck className="h-8 w-8 text-blue-600 mr-3" />
            Step-by-Step Verification Guide
          </h2>

          <div className="space-y-6">
            {/* Step 1 */}
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm mr-3">1</span>
                Install GPG
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Install GPG (GNU Privacy Guard) if not already installed.
                </p>
                <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono mb-4">
                  <div className="mb-2"># Windows (with Chocolatey)</div>
                  <div className="mb-2">choco install gnupg</div>
                  <div className="mb-2"># macOS (with Homebrew)</div>
                  <div className="mb-2">brew install gnupg</div>
                  <div className="mb-2"># Ubuntu/Debian</div>
                  <div>sudo apt-get install gnupg</div>
                </div>
              </div>
            </div>

            {/* Step 2 */}
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm mr-3">2</span>
                Import Public Key
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Import the JESUS IS KING public key to your GPG keyring.
                </p>
                <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono mb-4">
                  <div className="mb-2"># Download and import the key</div>
                  <div className="mb-2">curl -O https://downloads.jesusisking.app/keys/jesus-is-king-signing-key.asc</div>
                  <div className="mb-2">gpg --import jesus-is-king-signing-key.asc</div>
                  <div className="mb-2"># Verify the key fingerprint</div>
                  <div>gpg --fingerprint "JESUS IS KING"</div>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <p className="text-sm text-green-700">
                    Verify the fingerprint matches: <code>1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678</code>
                  </p>
                </div>
              </div>
            </div>

            {/* Step 3 */}
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm mr-3">3</span>
                Verify Signature
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Verify the downloaded file using its GPG signature.
                </p>
                <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono mb-4">
                  <div className="mb-2"># Verify the signature</div>
                  <div className="mb-2">gpg --verify jesus-is-king-windows-x64-1.0.0.exe.sig jesus-is-king-windows-x64-1.0.0.exe</div>
                  <div className="mb-2"># Expected output should include:</div>
                  <div>gpg: Good signature from "JESUS IS KING &lt;releases@jesusisking.app&gt;"</div>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <p className="text-sm text-green-700">
                    Look for "Good signature" in the output. Any other message indicates potential tampering.
                  </p>
                </div>
              </div>
            </div>

            {/* Step 4 */}
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center text-sm mr-3">4</span>
                Verify Checksum
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Double-check by verifying the SHA256 checksum matches exactly.
                </p>
                <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono mb-4">
                  <div className="mb-2"># Generate checksum</div>
                  <div className="mb-2">sha256sum jesus-is-king-windows-x64-1.0.0.exe</div>
                  <div className="mb-2"># Or on macOS:</div>
                  <div className="mb-2">shasum -a 256 jesus-is-king-windows-x64-1.0.0.exe</div>
                  <div className="mb-2"># Compare with official checksum above</div>
                </div>
                <div className="alert-warning">
                  <p className="text-sm">
                    The checksum must match exactly. Even one character difference indicates file corruption or tampering.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Scripture & Faith */}
        <section className="card bg-blue-50 border-blue-200 text-center">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">
            Wisdom in Verification
          </h3>
          <div className="scripture-verse text-center">
            "The simple believe anything, but the prudent give thought to their steps." - Proverbs 14:15
          </div>
          <p className="text-gray-600 mt-4">
            God calls us to be wise and discerning. Verifying downloads is an act of faithful stewardship,
            protecting the tools He has provided for secure communication.
          </p>
        </section>
      </div>
    </Layout>
  )
}