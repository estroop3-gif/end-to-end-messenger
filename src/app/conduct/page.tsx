'use client'

import Layout from '../../components/Layout'
import { Scale, Heart, Shield, Book, AlertTriangle, CheckCircle } from 'lucide-react'

export default function Conduct() {
  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Scale className="h-16 w-16 text-blue-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Code of Conduct
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Our platform is guided by Biblical principles and designed for lawful, ethical communication.
            These guidelines ensure our community reflects Christ's love while maintaining security.
          </p>
        </div>

        {/* Biblical Foundation */}
        <section className="mb-16">
          <div className="card bg-blue-50 border-blue-200 text-center">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">Founded on Scripture</h2>
            <div className="scripture-verse text-center">
              "Let your conversation be always full of grace, seasoned with salt,
              so that you may know how to answer everyone."
            </div>
            <p className="text-blue-600 font-medium mt-4">Colossians 4:6</p>
          </div>
        </section>

        {/* Core Principles */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Heart className="h-8 w-8 text-blue-600 mr-3" />
            Core Principles
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {[
              {
                title: 'Love Your Neighbor',
                description: 'Treat all users with respect, kindness, and Christ-like love.',
                verse: 'Mark 12:31'
              },
              {
                title: 'Speak Truth in Love',
                description: 'Communicate honestly while being gentle and constructive.',
                verse: 'Ephesians 4:15'
              },
              {
                title: 'Protect the Vulnerable',
                description: 'Use security features to protect those who cannot protect themselves.',
                verse: 'Psalm 82:3'
              },
              {
                title: 'Glorify God',
                description: 'Let all communications bring honor to God and advance His kingdom.',
                verse: '1 Corinthians 10:31'
              }
            ].map((principle, index) => (
              <div key={index} className="card">
                <h3 className="text-lg font-semibold text-gray-900 mb-3">{principle.title}</h3>
                <p className="text-gray-600 mb-3">{principle.description}</p>
                <p className="text-blue-600 text-sm font-medium">{principle.verse}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Acceptable Use */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <CheckCircle className="h-8 w-8 text-green-600 mr-3" />
            Acceptable Use
          </h2>
          <div className="card">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Encouraged Uses</h3>
                <ul className="space-y-2 text-gray-600">
                  <li className="flex items-start">
                    <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Faith-based discussions and Bible study</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Prayer requests and spiritual support</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Educational content about security and privacy</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Lawful personal and professional communication</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Legitimate privacy protection needs</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Supporting persecuted Christians worldwide</span>
                  </li>
                </ul>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Platform Goals</h3>
                <ul className="space-y-2 text-gray-600">
                  <li className="flex items-start">
                    <Shield className="h-5 w-5 text-blue-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Advance digital privacy and security education</span>
                  </li>
                  <li className="flex items-start">
                    <Shield className="h-5 w-5 text-blue-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Provide secure communication for legitimate needs</span>
                  </li>
                  <li className="flex items-start">
                    <Shield className="h-5 w-5 text-blue-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Foster Christian community and fellowship</span>
                  </li>
                  <li className="flex items-start">
                    <Shield className="h-5 w-5 text-blue-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Demonstrate Biblical principles in technology</span>
                  </li>
                  <li className="flex items-start">
                    <Shield className="h-5 w-5 text-blue-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Protect religious freedom and expression</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Prohibited Conduct */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <AlertTriangle className="h-8 w-8 text-red-600 mr-3" />
            Prohibited Conduct
          </h2>
          <div className="alert-danger">
            <div className="mb-4">
              <h3 className="text-lg font-semibold mb-2">Strictly Forbidden</h3>
              <p className="mb-4">
                The following activities are absolutely prohibited and will result in immediate termination
                of access and potential legal action:
              </p>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-3">Illegal Activities</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Any criminal activity or conspiracy</li>
                  <li>• Drug trafficking or illegal substance distribution</li>
                  <li>• Human trafficking or exploitation</li>
                  <li>• Financial fraud or money laundering</li>
                  <li>• Terrorism or violence planning</li>
                  <li>• Harassment, stalking, or threats</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-3">Harmful Content</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Child exploitation material (zero tolerance)</li>
                  <li>• Hate speech or discrimination</li>
                  <li>• Doxxing or sharing private information</li>
                  <li>• Malware or hacking tools distribution</li>
                  <li>• Copyright infringement</li>
                  <li>• Spam or unauthorized marketing</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Legal Compliance */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Scale className="h-8 w-8 text-blue-600 mr-3" />
            Legal Compliance
          </h2>
          <div className="card">
            <div className="alert-warning mb-6">
              <div className="flex items-start">
                <AlertTriangle className="h-5 w-5 mr-3 mt-0.5 flex-shrink-0" />
                <div>
                  <h4 className="font-semibold mb-2">Important Legal Notice</h4>
                  <p className="text-sm">
                    Users are responsible for complying with all applicable laws in their jurisdiction.
                    This platform does not provide legal advice and cannot protect against all legal risks.
                  </p>
                </div>
              </div>
            </div>
            <div className="space-y-4">
              <div>
                <h4 className="font-semibold text-gray-900 mb-2">User Responsibilities</h4>
                <ul className="text-gray-600 space-y-2 text-sm">
                  <li>• Comply with all local, state, and federal laws</li>
                  <li>• Respect intellectual property rights</li>
                  <li>• Follow export control regulations</li>
                  <li>• Obtain necessary permissions for communications</li>
                  <li>• Report suspected illegal activity</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-gray-900 mb-2">Platform Limitations</h4>
                <ul className="text-gray-600 space-y-2 text-sm">
                  <li>• We cannot guarantee legal protection</li>
                  <li>• We may comply with valid legal requests</li>
                  <li>• We reserve the right to suspend accounts</li>
                  <li>• We cannot prevent all monitoring by authorities</li>
                  <li>• Users assume responsibility for their usage</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Scripture Foundation */}
        <section className="card bg-blue-50 border-blue-200 text-center">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">
            Let Your Light Shine
          </h3>
          <div className="scripture-verse text-center">
            "In the same way, let your light shine before others, that they may see your good deeds
            and glorify your Father in heaven."
          </div>
          <p className="text-blue-600 font-medium mt-2 mb-4">Matthew 5:16</p>
          <p className="text-gray-600">
            Use this platform to be a light in the digital world. Let your communications reflect
            Christ's love, truth, and righteousness in all that you do.
          </p>
        </section>
      </div>
    </Layout>
  )
}