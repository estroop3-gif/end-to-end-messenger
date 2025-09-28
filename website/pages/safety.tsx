import Layout from '../components/Layout'
import Link from 'next/link'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Download,
  Eye,
  Wifi,
  HardDrive,
  Camera,
  Mic,
  Usb,
  Key,
  Lock,
  FileCheck,
  AlertCircle,
  Info
} from 'lucide-react'

export default function Safety() {
  return (
    <Layout
      title="Safety & Operational Security"
      description="Comprehensive guide to staying safe while using secure communications"
    >
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Shield className="h-16 w-16 text-primary-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Safety & Operational Security Guide
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Protecting your communications requires both strong encryption and proper operational security.
            Follow this guide to stay safe while using the JESUS IS KING platform.
          </p>
        </div>

        {/* Critical Warning */}
        <div className="danger mb-12">
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
                <Eye className="h-6 w-6 text-primary-600 mr-3" />
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
                <Usb className="h-6 w-6 text-primary-600 mr-3" />
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
                <HardDrive className="h-6 w-6 text-primary-600 mr-3" />
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
                <Wifi className="h-6 w-6 text-primary-600 mr-3" />
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
            <Download className="h-8 w-8 text-primary-600 mr-3" />
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
                <span className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm mr-3">1</span>
                Download Tails Safely
              </h3>
              <div className="ml-11">
                <p className="text-gray-600 mb-4">
                  Always download Tails from the official website and verify the download.
                </p>
                <div className="bg-gray-100 p-4 rounded-lg mb-4">
                  <p className="text-sm font-mono">
                    Official Site: <a href="https://tails.boum.org" target="_blank" rel="noopener noreferrer" className="text-primary-600 hover:underline">https://tails.boum.org</a>
                  </p>
                </div>
                <div className="warning">
                  <p className="text-sm">
                    <strong>Always verify the cryptographic signature</strong> to ensure the download hasn't been tampered with.
                    Follow the verification instructions on the official Tails website.
                  </p>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm mr-3">2</span>
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
                <div className="success">
                  <p className="text-sm">
                    Look for "Good signature from 'Tails developers'" in the verification output.
                  </p>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm mr-3">3</span>
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
                <div className="info">
                  <p className="text-sm">
                    <strong>Recommended:</strong> Create two Tails USBs - one for testing and one for actual use.
                  </p>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <span className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm mr-3">4</span>
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

        {/* External Drive Booting */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Usb className="h-8 w-8 text-primary-600 mr-3" />
            External Drive Only Booting
          </h2>

          <div className="info mb-6">
            <div className="flex items-start">
              <Info className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm">
                  <strong>Maximum Security Approach:</strong> For the highest level of operational security,
                  configure your system to boot exclusively from external drives. This prevents any potential
                  compromise of internal storage and ensures complete control over your computing environment.
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <HardDrive className="h-5 w-5 text-primary-600 mr-2" />
                BIOS/UEFI Configuration
              </h3>
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium mb-2">Step 1: Access BIOS/UEFI</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Restart computer and press F2, F12, DEL, or ESC during boot</li>
                    <li>• Look for "Setup," "BIOS," or "UEFI" on boot screen</li>
                    <li>• Consult your motherboard manual for specific key</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium mb-2">Step 2: Disable Internal Storage</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Navigate to "Storage" or "Drives" section</li>
                    <li>• Set SATA ports for internal drives to "Disabled"</li>
                    <li>• Or physically disconnect SATA/power cables</li>
                    <li>• Save and exit BIOS</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <Usb className="h-5 w-5 text-primary-600 mr-2" />
                External Boot Setup
              </h3>
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium mb-2">Boot Priority Configuration</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Set "USB Drive" as first boot priority</li>
                    <li>• Disable "Fast Boot" for better USB detection</li>
                    <li>• Enable "Legacy USB Support" if needed</li>
                    <li>• Set "Boot Mode" to UEFI for modern drives</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium mb-2">Security Settings</h4>
                  <ul className="text-sm text-gray-600 space-y-1 ml-4">
                    <li>• Enable Secure Boot (if using signed OS)</li>
                    <li>• Set BIOS/UEFI password protection</li>
                    <li>• Disable network boot (PXE boot)</li>
                    <li>• Disable unused ports if possible</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>

          <div className="warning mt-6">
            <div className="flex items-start">
              <AlertTriangle className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="font-semibold mb-2">Important Considerations</h4>
                <ul className="text-sm space-y-1">
                  <li>• Always keep backup external drives with identical configuration</li>
                  <li>• Test external boot before relying on it for critical operations</li>
                  <li>• Some laptops may require disabling "Fast Startup" in Windows first</li>
                  <li>• Modern UEFI systems may require signed bootloaders for Secure Boot</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Hardware Isolation Theory */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Camera className="h-8 w-8 text-primary-600 mr-3" />
            Hardware Isolation Theory
          </h2>

          <div className="danger mb-6">
            <div className="flex items-start">
              <AlertTriangle className="h-6 w-6 mr-3 mt-1 flex-shrink-0" />
              <div>
                <h3 className="text-lg font-semibold mb-2">⚠️ THEORETICAL DISCUSSION ONLY</h3>
                <p className="mb-4">
                  <strong>WARNING: The following is for educational and theoretical understanding only.</strong>
                  We strongly recommend AGAINST performing any destructive hardware modifications.
                  These actions can damage devices, void warranties, create safety hazards, and may be illegal in some jurisdictions.
                </p>
                <p className="text-sm">
                  <strong>Use safe alternatives instead:</strong> External peripherals, hardware switches, Faraday bags, or air-gapped systems.
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <Camera className="h-5 w-5 text-orange-600 mr-2" />
                Camera Isolation Theory
              </h3>
              <div className="space-y-3">
                <p className="text-sm text-gray-600">
                  <strong>Theoretical concept:</strong> Physically disconnecting camera modules by removing ribbon cables or power connections.
                </p>
                <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                  <h4 className="font-semibold text-red-800 text-sm mb-2">Risks & Problems:</h4>
                  <ul className="text-xs text-red-700 space-y-1">
                    <li>• Permanent device damage</li>
                    <li>• Voided warranty</li>
                    <li>• Static electricity damage</li>
                    <li>• Difficult reassembly</li>
                    <li>• May affect other components</li>
                  </ul>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <h4 className="font-semibold text-green-800 text-sm mb-2">Safe Alternatives:</h4>
                  <ul className="text-xs text-green-700 space-y-1">
                    <li>• Physical camera covers</li>
                    <li>• External webcam (disconnect when not needed)</li>
                    <li>• Laptops with hardware camera switches</li>
                    <li>• Software camera blocking</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <Mic className="h-5 w-5 text-orange-600 mr-2" />
                Microphone Isolation Theory
              </h3>
              <div className="space-y-3">
                <p className="text-sm text-gray-600">
                  <strong>Theoretical concept:</strong> Physically disconnecting microphone arrays by cutting connections or removing components.
                </p>
                <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                  <h4 className="font-semibold text-red-800 text-sm mb-2">Risks & Problems:</h4>
                  <ul className="text-xs text-red-700 space-y-1">
                    <li>• Multiple microphones in modern devices</li>
                    <li>• Integrated circuits hard to isolate</li>
                    <li>• Risk of short circuits</li>
                    <li>• May affect audio output</li>
                    <li>• Irreversible modifications</li>
                  </ul>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <h4 className="font-semibold text-green-800 text-sm mb-2">Safe Alternatives:</h4>
                  <ul className="text-xs text-green-700 space-y-1">
                    <li>• External USB microphone (unplug when not needed)</li>
                    <li>• Audio interfaces with physical switches</li>
                    <li>• Software microphone muting</li>
                    <li>• Faraday cage environments</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <HardDrive className="h-5 w-5 text-orange-600 mr-2" />
                Storage Isolation Theory
              </h3>
              <div className="space-y-3">
                <p className="text-sm text-gray-600">
                  <strong>Theoretical concept:</strong> Physically removing internal storage to prevent any digital signatures or data persistence.
                </p>
                <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                  <h4 className="font-semibold text-red-800 text-sm mb-2">Risks & Problems:</h4>
                  <ul className="text-xs text-red-700 space-y-1">
                    <li>• System won't boot without storage</li>
                    <li>• UEFI/BIOS settings may be lost</li>
                    <li>• Firmware updates impossible</li>
                    <li>• Reduced system functionality</li>
                    <li>• Hardware warranty void</li>
                  </ul>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <h4 className="font-semibold text-green-800 text-sm mb-2">Safe Alternatives:</h4>
                  <ul className="text-xs text-green-700 space-y-1">
                    <li>• External drive only booting (see above)</li>
                    <li>• Full disk encryption on removable drives</li>
                    <li>• Live OS environments (Tails, etc.)</li>
                    <li>• Air-gapped dedicated systems</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>

          <div className="success mt-6">
            <div className="flex items-start">
              <CheckCircle className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="font-semibold mb-2">Recommended Safe Approach</h4>
                <p className="text-sm">
                  Instead of hardware modifications, use <strong>dedicated air-gapped systems</strong> with external peripherals,
                  <strong>live operating systems</strong> on external drives, and <strong>physical isolation techniques</strong>
                  like Faraday bags for radio isolation. This provides excellent security without device damage.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Binary Verification */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <FileCheck className="h-8 w-8 text-primary-600 mr-3" />
            Binary Verification Guide
          </h2>

          <p className="text-gray-600 mb-6">
            Always verify downloaded binaries to ensure they haven't been tampered with.
            This applies to both the JESUS IS KING platform and any other security software.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <Key className="h-5 w-5 text-primary-600 mr-2" />
                GPG Signature Verification
              </h3>
              <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono mb-4">
                <div className="mb-2"># Import public key</div>
                <div className="mb-2">gpg --import pubkey.asc</div>
                <div className="mb-2"># Verify signature</div>
                <div>gpg --verify app.sig app.exe</div>
              </div>
              <div className="success text-sm">
                Look for "Good signature" and verify the key fingerprint matches official documentation.
              </div>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <Lock className="h-5 w-5 text-primary-600 mr-2" />
                Checksum Verification
              </h3>
              <div className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm font-mono mb-4">
                <div className="mb-2"># Generate SHA256 checksum</div>
                <div className="mb-2">sha256sum app.exe</div>
                <div className="mb-2"># Compare with official</div>
                <div>cat app.exe.sha256</div>
              </div>
              <div className="warning text-sm">
                Checksums must match exactly. Even one character difference indicates tampering.
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

        {/* Additional Resources */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Additional Security Resources
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Official Documentation</h3>
              <ul className="space-y-2 text-gray-600">
                <li><Link href="/downloads" className="text-primary-600 hover:underline">Download & Verification</Link></li>
                <li><Link href="/how-to-use" className="text-primary-600 hover:underline">How to Use Guide</Link></li>
                <li><Link href="/docs/shuttle_protocol" className="text-primary-600 hover:underline">Shuttle Protocol Docs</Link></li>
                <li><Link href="/legal" className="text-primary-600 hover:underline">Legal & Compliance</Link></li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4">External Resources</h3>
              <ul className="space-y-2 text-gray-600 text-sm">
                <li>• <a href="https://tails.boum.org" target="_blank" rel="noopener noreferrer" className="text-primary-600 hover:underline">Tails OS Official Site <ExternalLink className="h-3 w-3 inline ml-1" /></a></li>
                <li>• <a href="https://ssd.eff.org" target="_blank" rel="noopener noreferrer" className="text-primary-600 hover:underline">EFF Surveillance Self-Defense <ExternalLink className="h-3 w-3 inline ml-1" /></a></li>
                <li>• <a href="https://securityinabox.org" target="_blank" rel="noopener noreferrer" className="text-primary-600 hover:underline">Security in a Box <ExternalLink className="h-3 w-3 inline ml-1" /></a></li>
                <li>• Hardware vendors with privacy features</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Scripture & Faith */}
        <section className="prayer-card text-center">
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