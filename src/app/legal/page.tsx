'use client'

import Layout from '../../components/Layout'
import { Scale, AlertTriangle, Info, Shield } from 'lucide-react'

export default function Legal() {
  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Scale className="h-16 w-16 text-blue-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Legal & Compliance
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Important legal information, disclaimers, and compliance requirements for using
            the JESUS IS KING secure messaging platform.
          </p>
        </div>

        {/* Critical Warning */}
        <section className="mb-16">
          <div className="alert-danger">
            <div className="flex items-start">
              <AlertTriangle className="h-6 w-6 mr-3 mt-1 flex-shrink-0" />
              <div>
                <h3 className="text-lg font-semibold mb-2">⚠️ EDUCATIONAL USE ONLY</h3>
                <p className="mb-4">
                  <strong>This platform is designed for educational purposes and lawful communication only.</strong>
                  Users must comply with all applicable laws and regulations in their jurisdiction.
                  This software is not intended for illegal activities.
                </p>
                <p className="text-sm">
                  By using this platform, you acknowledge that you understand and accept all legal
                  responsibilities associated with its use.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Disclaimer */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Info className="h-8 w-8 text-blue-600 mr-3" />
            Legal Disclaimer
          </h2>
          <div className="card">
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">No Legal Advice</h3>
                <p className="text-gray-600">
                  This platform and its documentation do not constitute legal advice. Users should
                  consult with qualified legal counsel regarding the legality of encryption, secure
                  communications, and privacy tools in their specific jurisdiction.
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">No Guarantees</h3>
                <p className="text-gray-600">
                  While we implement strong security measures, we cannot guarantee complete security
                  or privacy. Users should understand the risks and limitations of any security software.
                  No technology is 100% secure against all threats.
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">User Responsibility</h3>
                <p className="text-gray-600">
                  Users are solely responsible for their use of this platform and must ensure
                  compliance with all applicable laws, regulations, and institutional policies.
                  Users assume all risks associated with the use of this software.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Export Controls */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Shield className="h-8 w-8 text-blue-600 mr-3" />
            Export Control Compliance
          </h2>
          <div className="card">
            <div className="alert-warning mb-6">
              <div className="flex items-start">
                <AlertTriangle className="h-5 w-5 mr-3 mt-0.5 flex-shrink-0" />
                <div>
                  <h4 className="font-semibold mb-2">Encryption Export Restrictions</h4>
                  <p className="text-sm">
                    This software contains cryptographic functionality that may be subject to
                    export control laws in various countries. Users are responsible for
                    compliance with applicable export control regulations.
                  </p>
                </div>
              </div>
            </div>
            <div className="space-y-4">
              <div>
                <h4 className="font-semibold text-gray-900 mb-2">United States</h4>
                <p className="text-gray-600 text-sm">
                  This software may be subject to U.S. Export Administration Regulations (EAR).
                  Export or re-export may require appropriate licenses from the U.S. Department of Commerce.
                </p>
              </div>
              <div>
                <h4 className="font-semibold text-gray-900 mb-2">International</h4>
                <p className="text-gray-600 text-sm">
                  Many countries have restrictions on the import, export, or use of encryption software.
                  Users must research and comply with regulations in their jurisdiction.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Terms of Use */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">Terms of Use</h2>
          <div className="card">
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Acceptance of Terms</h3>
                <p className="text-gray-600">
                  By downloading, installing, or using this software, you agree to be bound by these
                  terms and conditions. If you do not agree to these terms, do not use this software.
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Permitted Use</h3>
                <p className="text-gray-600">
                  This software is provided for educational, research, and lawful communication purposes.
                  Commercial use may be permitted but should be discussed with the development team.
                  Any illegal use is strictly prohibited.
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Prohibited Activities</h3>
                <ul className="text-gray-600 space-y-2 text-sm">
                  <li>• Using the software for any illegal purpose</li>
                  <li>• Attempting to circumvent security measures</li>
                  <li>• Reverse engineering for malicious purposes</li>
                  <li>• Distributing modified versions without permission</li>
                  <li>• Using the platform to harm others</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Privacy Policy */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">Privacy Policy</h2>
          <div className="card">
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Data Collection</h3>
                <p className="text-gray-600">
                  We are committed to privacy by design. The platform is designed to minimize data
                  collection and maximize user privacy. We do not collect personal information
                  beyond what is necessary for operation.
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">End-to-End Encryption</h3>
                <p className="text-gray-600">
                  Messages are encrypted end-to-end, meaning only the sender and intended recipient
                  can read them. We cannot access the content of your communications.
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Legal Requests</h3>
                <p className="text-gray-600">
                  While we design for privacy, we may be required to comply with valid legal requests
                  from law enforcement. However, end-to-end encryption limits what information
                  could be provided.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Liability Limitation */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">Limitation of Liability</h2>
          <div className="card">
            <div className="alert-warning mb-4">
              <p className="text-sm font-semibold">
                IMPORTANT: READ THIS SECTION CAREFULLY
              </p>
            </div>
            <div className="space-y-4 text-sm text-gray-600">
              <p>
                TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE DEVELOPERS AND CONTRIBUTORS OF THIS
                SOFTWARE SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
                CONSEQUENTIAL, OR PUNITIVE DAMAGES ARISING OUT OF OR RELATING TO THE USE OF THIS SOFTWARE.
              </p>
              <p>
                THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS
                OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
                FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
              </p>
              <p>
                Users acknowledge that they use this software at their own risk and that the
                developers make no guarantees about security, privacy, or legal protection.
              </p>
            </div>
          </div>
        </section>

        {/* Contact */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">Legal Questions</h2>
          <div className="card">
            <p className="text-gray-600 mb-4">
              If you have questions about the legal aspects of using this software, please:
            </p>
            <ul className="text-gray-600 space-y-2">
              <li>• Consult with qualified legal counsel in your jurisdiction</li>
              <li>• Research applicable laws and regulations</li>
              <li>• Contact your institutional legal department if applicable</li>
              <li>• Review the documentation and code of conduct carefully</li>
            </ul>
          </div>
        </section>

        {/* Scripture */}
        <section className="card bg-blue-50 border-blue-200 text-center">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">
            Wisdom in All Things
          </h3>
          <div className="scripture-verse text-center">
            "Let everyone be subject to the governing authorities, for there is no authority
            except that which God has established."
          </div>
          <p className="text-blue-600 font-medium mt-2 mb-4">Romans 13:1</p>
          <p className="text-gray-600">
            We are called to respect legitimate authority while also protecting the vulnerable.
            Use this platform wisely, lawfully, and in accordance with God's will.
          </p>
        </section>
      </div>
    </Layout>
  )
}