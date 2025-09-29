'use client'

import Layout from '../../components/Layout'
import {
  Download,
  AlertTriangle,
  Key,
  FileCheck,
  Copy
} from 'lucide-react'

export default function Downloads() {
  const downloads = [
    {
      platform: 'Windows',
      version: '1.0.0',
      size: '862 KB',
      file: 'jesus-is-king-messenger-windows.exe',
      sha256: '7f42c1d9f10b0589a5946485e4d219acc7e5813e7f8ebf06cfc7a5c3a930c9ee',
      signature: 'jesus-is-king-messenger-windows.exe.sig',
      download_url: '/downloads/jesus-is-king-messenger-windows.exe',
      status: 'available',
      instructions: 'Double-click to run, or use command line with: verse, keygen, chat, security'
    },
    {
      platform: 'Linux',
      version: '1.0.0',
      size: '1.9 MB',
      file: 'jesus-is-king-linux-x64-1.0.0.AppImage',
      sha256: '074f60a81147445431b45cb0febb4f83838a8281416402357bf349b6bee962ea',
      signature: 'jesus-is-king-linux-x64-1.0.0.AppImage.sig',
      download_url: '/downloads/jesus-is-king-linux-x64-1.0.0.AppImage',
      status: 'available',
      instructions: 'Download and run: chmod +x jesus-is-king-linux-x64-1.0.0.AppImage && ./jesus-is-king-linux-x64-1.0.0.AppImage'
    }
  ]

  const upcomingDownloads = [
    {
      platform: 'macOS',
      version: '1.0.0',
      status: 'coming_soon',
      reason: 'macOS cross-compilation requires Apple development tools',
      eta: 'Available soon - macOS users can use the Linux version with compatible tools'
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
                    {download.instructions && (
                      <div className="mt-2">
                        <p className="text-sm text-gray-500 mb-2">Installation:</p>
                        <code className="text-xs bg-gray-100 px-2 py-1 rounded block">
                          {download.instructions}
                        </code>
                      </div>
                    )}
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
                      href={'/downloads/' + download.signature}
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

        {/* Upcoming Downloads Section */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <AlertTriangle className="h-8 w-8 text-amber-600 mr-3" />
            Coming Soon
          </h2>

          <div className="space-y-6">
            {upcomingDownloads.map((download, index) => (
              <div key={index} className="card border-amber-200 bg-amber-50">
                <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
                  <div className="mb-4 lg:mb-0">
                    <h3 className="text-lg font-semibold text-gray-900 mb-2 flex items-center">
                      {download.platform} v{download.version}
                      <span className="ml-3 px-2 py-1 bg-amber-200 text-amber-800 text-sm rounded">
                        Coming Soon
                      </span>
                    </h3>
                    <p className="text-gray-600 mb-2">
                      <strong>Status:</strong> {download.reason}
                    </p>
                    <p className="text-gray-600">
                      <strong>Alternative:</strong> {download.eta}
                    </p>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-3">
                    <button
                      disabled
                      className="btn-outline opacity-50 cursor-not-allowed inline-flex items-center justify-center"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Not Available Yet
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="alert-info mt-6">
            <h4 className="font-semibold mb-4">🔧 Alternative Installation Guide for Windows Users</h4>
            <p className="mb-6">
              <strong>Native Windows version is now available above!</strong> However, you can also run the Linux version using Windows Subsystem for Linux (WSL) if preferred.
              This provides the <strong>exact same functionality</strong> as the native Linux version with full encryption support.
            </p>

            <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
              <h5 className="font-semibold text-green-800 mb-2">⚡ Quick Start (5 minutes)</h5>
              <p className="text-green-700 text-sm">
                Most Windows 10/11 users can get up and running in under 5 minutes using WSL.
                No technical expertise required - just follow the numbered steps below!
              </p>
            </div>

            <div className="space-y-6">
              {/* WSL Method */}
              <div className="border-l-4 border-blue-500 pl-4">
                <h5 className="font-semibold text-lg mb-3">✅ Method 1: WSL (Recommended - Easy Setup)</h5>

                <div className="space-y-4">
                  <div>
                    <h6 className="font-medium mb-2">Step 1: Install WSL</h6>
                    <ol className="list-decimal list-inside space-y-1 text-sm ml-4">
                      <li>Open <strong>Command Prompt</strong> or <strong>PowerShell</strong> as Administrator</li>
                      <li>Run: <code className="bg-gray-200 px-1 rounded">wsl --install</code></li>
                      <li>Restart your computer when prompted</li>
                      <li>After restart, Ubuntu will automatically open and complete setup</li>
                      <li>Create a username and password when prompted</li>
                    </ol>
                  </div>

                  <div>
                    <h6 className="font-medium mb-2">Step 2: Download and Run JESUS IS KING Messenger</h6>
                    <ol className="list-decimal list-inside space-y-1 text-sm ml-4">
                      <li>Open Ubuntu from your Start Menu</li>
                      <li>Download the Linux version:
                        <div className="bg-gray-900 text-green-400 p-2 rounded mt-1 font-mono text-xs">
                          wget https://jesusisking.app/downloads/jesus-is-king-linux-x64-1.0.0.AppImage
                        </div>
                      </li>
                      <li>Make it executable:
                        <div className="bg-gray-900 text-green-400 p-2 rounded mt-1 font-mono text-xs">
                          chmod +x jesus-is-king-linux-x64-1.0.0.AppImage
                        </div>
                      </li>
                      <li>Run the application:
                        <div className="bg-gray-900 text-green-400 p-2 rounded mt-1 font-mono text-xs">
                          ./jesus-is-king-linux-x64-1.0.0.AppImage verse
                        </div>
                      </li>
                      <li>Start secure messaging:
                        <div className="bg-gray-900 text-green-400 p-2 rounded mt-1 font-mono text-xs">
                          ./jesus-is-king-linux-x64-1.0.0.AppImage chat
                        </div>
                      </li>
                    </ol>
                  </div>
                </div>
              </div>

              {/* Alternative Methods */}
              <div className="border-l-4 border-amber-500 pl-4">
                <h5 className="font-semibold text-lg mb-3">⚙️ Alternative Methods</h5>

                <div className="space-y-4">
                  <div>
                    <h6 className="font-medium mb-2">Method 2: Docker Desktop</h6>
                    <ol className="list-decimal list-inside space-y-1 text-sm ml-4">
                      <li>Install <a href="https://docs.docker.com/desktop/install/windows-install/" className="text-blue-600 underline">Docker Desktop for Windows</a></li>
                      <li>Open Command Prompt and run:
                        <div className="bg-gray-900 text-green-400 p-2 rounded mt-1 font-mono text-xs">
                          docker run -it --rm ubuntu:22.04 bash
                        </div>
                      </li>
                      <li>Inside the container, install and run:
                        <div className="bg-gray-900 text-green-400 p-2 rounded mt-1 font-mono text-xs space-y-1">
                          <div>apt update && apt install -y wget</div>
                          <div>wget https://jesusisking.app/downloads/jesus-is-king-linux-x64-1.0.0.AppImage</div>
                          <div>chmod +x jesus-is-king-linux-x64-1.0.0.AppImage</div>
                          <div>./jesus-is-king-linux-x64-1.0.0.AppImage chat</div>
                        </div>
                      </li>
                    </ol>
                  </div>

                  <div>
                    <h6 className="font-medium mb-2">Method 3: VirtualBox (Full Linux Experience)</h6>
                    <ol className="list-decimal list-inside space-y-1 text-sm ml-4">
                      <li>Download and install <a href="https://www.virtualbox.org/wiki/Downloads" className="text-blue-600 underline">VirtualBox</a></li>
                      <li>Download <a href="https://ubuntu.com/download/desktop" className="text-blue-600 underline">Ubuntu Desktop ISO</a></li>
                      <li>Create a new VM with at least 2GB RAM and 20GB storage</li>
                      <li>Install Ubuntu following the setup wizard</li>
                      <li>Download and run the Linux AppImage as shown in Method 1</li>
                    </ol>
                  </div>
                </div>
              </div>

              {/* Troubleshooting */}
              <div className="border-l-4 border-red-500 pl-4">
                <h5 className="font-semibold text-lg mb-3">🛠️ Troubleshooting</h5>

                <div className="space-y-3 text-sm">
                  <div>
                    <strong>WSL not installing?</strong>
                    <ul className="list-disc list-inside ml-4 mt-1">
                      <li>Ensure you're running Windows 10 version 2004+ or Windows 11</li>
                      <li>Enable "Virtual Machine Platform" in Windows Features</li>
                      <li>Try: <code className="bg-gray-200 px-1 rounded">wsl --install -d Ubuntu</code></li>
                    </ul>
                  </div>

                  <div>
                    <strong>AppImage won't run?</strong>
                    <ul className="list-disc list-inside ml-4 mt-1">
                      <li>Install required packages: <code className="bg-gray-200 px-1 rounded">sudo apt update && sudo apt install fuse</code></li>
                      <li>Check file permissions: <code className="bg-gray-200 px-1 rounded">ls -la jesus-is-king-*.AppImage</code></li>
                    </ul>
                  </div>

                  <div>
                    <strong>Need help?</strong>
                    <ul className="list-disc list-inside ml-4 mt-1">
                      <li>Run: <code className="bg-gray-200 px-1 rounded">./jesus-is-king-linux-x64-1.0.0.AppImage --help</code></li>
                      <li>Check the verification instructions below for security</li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* Security Note */}
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h5 className="font-semibold text-blue-800 mb-2">🔒 Security Reminder</h5>
                <p className="text-blue-700 text-sm">
                  Always verify the downloaded file using the SHA256 checksum and GPG signature shown below
                  before running. This ensures you have the authentic, unmodified JESUS IS KING messenger.
                </p>
              </div>
            </div>

            <p className="mt-6 text-sm font-medium">
              📢 We're actively working on native Windows support and will update this page when available.
            </p>
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
                href="/downloads/keys/jesus-is-king-signing-key.asc"
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
                  <div className="mb-2">curl -O https://your-domain.com/downloads/keys/jesus-is-king-signing-key.asc</div>
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
                  <div className="mb-2"># Verify the signature (Windows)</div>
                  <div className="mb-2">gpg --verify jesus-is-king-messenger-windows.exe.sig jesus-is-king-messenger-windows.exe</div>
                  <div className="mb-2"># Or for Linux:</div>
                  <div className="mb-2">gpg --verify jesus-is-king-linux-x64-1.0.0.AppImage.sig jesus-is-king-linux-x64-1.0.0.AppImage</div>
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
                  <div className="mb-2"># Generate checksum (Windows)</div>
                  <div className="mb-2">sha256sum jesus-is-king-messenger-windows.exe</div>
                  <div className="mb-2"># Or for Linux:</div>
                  <div className="mb-2">sha256sum jesus-is-king-linux-x64-1.0.0.AppImage</div>
                  <div className="mb-2"># On macOS:</div>
                  <div className="mb-2">shasum -a 256 [filename]</div>
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