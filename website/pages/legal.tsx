import Layout from '../components/Layout'
import Link from 'next/link'
import {
  Scale,
  Shield,
  AlertTriangle,
  Book,
  ExternalLink,
  Globe,
  Gavel,
  FileText,
  Info
} from 'lucide-react'

export default function Legal() {
  const jurisdictions = [
    {
      region: 'United States',
      considerations: [
        'First Amendment protections for cryptographic code',
        'Export Administration Regulations (EAR) compliance',
        'State and federal privacy laws',
        'Constitutional protections against unreasonable search'
      ],
      restrictions: [
        'Must comply with lawful intercept orders',
        'Cannot be used to facilitate criminal activity',
        'Subject to national security considerations'
      ]
    },
    {
      region: 'European Union',
      considerations: [
        'GDPR compliance for personal data processing',
        'Strong encryption generally legal',
        'Digital Services Act obligations',
        'E-Privacy Directive requirements'
      ],
      restrictions: [
        'Some countries restrict strong encryption',
        'Must comply with lawful access orders',
        'Subject to terrorism prevention laws'
      ]
    },
    {
      region: 'Other Jurisdictions',
      considerations: [
        'Laws vary significantly by country',
        'Some nations prohibit or restrict encryption',
        'Import/export restrictions may apply',
        'Religious freedom protections vary'
      ],
      restrictions: [
        'Encryption may be illegal or restricted',
        'Severe penalties for violations',
        'Government surveillance requirements',
        'Consult local legal counsel required'
      ]
    }
  ]

  const disclaimers = [
    {
      title: 'Educational Purpose',
      content: 'This platform is designed primarily for educational purposes, including learning about cryptography, secure communications, and digital privacy. While it provides real security features, its primary intent is educational and demonstration of security principles.'
    },
    {
      title: 'No Warranty',
      content: 'This software is provided "as is" without warranty of any kind, express or implied. The developers make no guarantees about the software\'s security, reliability, or fitness for any particular purpose.'
    },
    {
      title: 'User Responsibility',
      content: 'Users are solely responsible for their use of this platform and must ensure compliance with all applicable laws in their jurisdiction. Users must not use this platform for illegal activities.'
    },
    {
      title: 'No Legal Advice',
      content: 'Nothing on this platform constitutes legal advice. Users should consult qualified legal counsel for guidance on laws applicable to their situation and jurisdiction.'
    },
    {
      title: 'Export Controls',
      content: 'This software may be subject to export control laws. Users are responsible for compliance with all applicable export and import regulations when distributing or using this software.'
    }
  ]

  return (
    <Layout
      title="Legal & Compliance"
      description="Legal information, disclaimers, and compliance guidance for the JESUS IS KING platform"
    >
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Scale className="h-16 w-16 text-primary-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Legal & Compliance
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Important legal information, disclaimers, and compliance guidance for using
            the JESUS IS KING secure messaging platform responsibly and lawfully.
          </p>
        </div>

        {/* Scripture Foundation */}
        <div className="prayer-card text-center mb-12">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">
            Biblical Foundation for Legal Compliance
          </h2>
          <div className="scripture-verse text-center">
            "Let everyone be subject to the governing authorities, for there is no authority
            except that which God has established. The authorities that exist have been
            established by God." - Romans 13:1
          </div>
        </div>

        {/* Critical Legal Notice */}
        <div className="danger mb-12">
          <div className="flex items-start">
            <AlertTriangle className="h-8 w-8 mr-4 mt-1 flex-shrink-0" />
            <div>
              <h3 className="text-2xl font-semibold mb-4">⚖️ CRITICAL LEGAL NOTICE</h3>
              <div className="space-y-4 text-sm">
                <p>
                  <strong>EDUCATIONAL USE ONLY:</strong> This platform is designed for educational
                  purposes and lawful communication only. It is NOT intended for illegal activities,
                  circumventing lawful investigations, or violating any applicable laws or regulations.
                </p>
                <p>
                  <strong>USER RESPONSIBILITY:</strong> Users are solely and fully responsible for
                  ensuring their use complies with all applicable laws in their jurisdiction.
                  Encryption laws, privacy regulations, and communication restrictions vary
                  significantly by country and region.
                </p>
                <p>
                  <strong>NO LEGAL PROTECTION:</strong> This platform does not provide legal immunity
                  or protection from prosecution. Users who violate laws may face serious legal
                  consequences including criminal prosecution.
                </p>
                <p>
                  <strong>COOPERATION WITH AUTHORITIES:</strong> The platform operators will cooperate
                  with lawful requests from authorized government agencies and may provide information
                  when legally required to do so.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Jurisdictional Considerations */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Globe className="h-8 w-8 text-primary-600 mr-3" />
            Jurisdictional Considerations
          </h2>

          <div className="space-y-6">
            {jurisdictions.map((jurisdiction, index) => (
              <div key={index} className="card">
                <h3 className="text-xl font-semibold text-gray-900 mb-4">
                  {jurisdiction.region}
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="font-semibold text-green-800 mb-3">Legal Considerations</h4>
                    <ul className="space-y-2">
                      {jurisdiction.considerations.map((item, itemIndex) => (
                        <li key={itemIndex} className="text-sm text-gray-600 flex items-start">
                          <Shield className="h-4 w-4 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-semibold text-red-800 mb-3">Restrictions & Obligations</h4>
                    <ul className="space-y-2">
                      {jurisdiction.restrictions.map((item, itemIndex) => (
                        <li key={itemIndex} className="text-sm text-gray-600 flex items-start">
                          <AlertTriangle className="h-4 w-4 text-red-500 mr-2 mt-0.5 flex-shrink-0" />
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="warning mt-6">
            <div className="flex items-start">
              <Gavel className="h-5 w-5 text-yellow-600 mr-3 mt-0.5" />
              <div>
                <h4 className="font-semibold text-yellow-800 mb-2">Legal Counsel Required</h4>
                <p className="text-yellow-700 text-sm">
                  This information is general and not comprehensive. Users must consult qualified
                  legal counsel familiar with their local jurisdiction for specific guidance.
                  Laws change frequently and vary significantly by location.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Terms and Disclaimers */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <FileText className="h-8 w-8 text-primary-600 mr-3" />
            Terms and Disclaimers
          </h2>

          <div className="space-y-6">
            {disclaimers.map((disclaimer, index) => (
              <div key={index} className="card">
                <h3 className="text-lg font-semibold text-gray-900 mb-3">
                  {disclaimer.title}
                </h3>
                <p className="text-gray-600 text-sm leading-relaxed">
                  {disclaimer.content}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* Specific Legal Requirements */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Specific Legal Requirements by Category
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Encryption & Cryptography
              </h3>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Export/import controls may apply</li>
                <li>• Some countries restrict or prohibit strong encryption</li>
                <li>• Key escrow requirements in certain jurisdictions</li>
                <li>• Registration or licensing may be required</li>
                <li>• Academic research exceptions may apply</li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Communications & Privacy
              </h3>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Lawful intercept capabilities may be required</li>
                <li>• Data retention obligations vary by jurisdiction</li>
                <li>• Cross-border data transfer restrictions</li>
                <li>• Consent requirements for recording/monitoring</li>
                <li>• Right to privacy vs. law enforcement balance</li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Religious & Free Speech
              </h3>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Religious freedom protections vary globally</li>
                <li>• Blasphemy laws in some jurisdictions</li>
                <li>• Restrictions on religious content or symbols</li>
                <li>• Missionary activity regulations</li>
                <li>• Cultural sensitivity requirements</li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Business & Commercial Use
              </h3>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Commercial encryption licenses may be required</li>
                <li>• Industry-specific compliance requirements</li>
                <li>• Professional licensing for certain uses</li>
                <li>• Tax obligations for commercial activities</li>
                <li>• Corporate governance and reporting duties</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Compliance Guidelines */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Compliance Guidelines
          </h2>

          <div className="space-y-6">
            <div className="card bg-blue-50 border-blue-200">
              <h3 className="text-lg font-semibold text-blue-800 mb-4">
                Before Using This Platform
              </h3>
              <ol className="text-sm text-blue-700 space-y-2">
                <li>1. <strong>Research local laws</strong> - Understand encryption and communication laws in your jurisdiction</li>
                <li>2. <strong>Consult legal counsel</strong> - Get professional advice for your specific situation</li>
                <li>3. <strong>Verify export/import compliance</strong> - Check if software transfer restrictions apply</li>
                <li>4. <strong>Understand your obligations</strong> - Know what you must and must not do</li>
                <li>5. <strong>Plan for legal scenarios</strong> - Consider how you'll handle lawful requests</li>
              </ol>
            </div>

            <div className="card bg-green-50 border-green-200">
              <h3 className="text-lg font-semibold text-green-800 mb-4">
                Recommended Best Practices
              </h3>
              <ul className="text-sm text-green-700 space-y-2">
                <li>• Maintain detailed records of legal research and compliance efforts</li>
                <li>• Regularly review and update legal compliance as laws change</li>
                <li>• Use platform only for clearly lawful purposes</li>
                <li>• Cooperate fully with lawful government requests</li>
                <li>• Seek guidance when in doubt rather than proceeding</li>
                <li>• Document business justification for encryption use</li>
              </ul>
            </div>

            <div className="card bg-yellow-50 border-yellow-200">
              <h3 className="text-lg font-semibold text-yellow-800 mb-4">
                Warning Signs to Stop and Seek Help
              </h3>
              <ul className="text-sm text-yellow-700 space-y-2">
                <li>• Unclear about legal status of intended use</li>
                <li>• Pressure from others to use for questionable purposes</li>
                <li>• Operating in high-risk or restrictive jurisdictions</li>
                <li>• Requests to circumvent known legal requirements</li>
                <li>• Any suggestion to use for illegal activities</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Law Enforcement Cooperation */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Law Enforcement Cooperation
          </h2>

          <div className="card">
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">
                Our Cooperation Policy
              </h3>
              <p className="text-gray-600 text-sm mb-4">
                We are committed to operating within the law and cooperating with legitimate
                law enforcement activities. Our approach is guided by Biblical principles
                of respecting governing authorities while protecting user privacy.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold text-gray-900 mb-3">What We Will Do</h4>
                <ul className="text-sm text-gray-600 space-y-2">
                  <li>• Respond to valid legal process (warrants, subpoenas)</li>
                  <li>• Provide available technical assistance when legally required</li>
                  <li>• Cooperate with investigations of illegal activity</li>
                  <li>• Comply with applicable data retention requirements</li>
                  <li>• Report suspected criminal activity when legally obligated</li>
                </ul>
              </div>

              <div>
                <h4 className="font-semibold text-gray-900 mb-3">What We Cannot/Will Not Do</h4>
                <ul className="text-sm text-gray-600 space-y-2">
                  <li>• Break encryption for data we cannot access</li>
                  <li>• Provide assistance beyond our technical capabilities</li>
                  <li>• Comply with requests lacking proper legal authority</li>
                  <li>• Violate our users' legal rights without due process</li>
                  <li>• Assist in activities that violate our code of conduct</li>
                </ul>
              </div>
            </div>

            <div className="mt-6 p-4 bg-gray-100 rounded-lg">
              <p className="text-gray-700 text-sm">
                <strong>Transparency Note:</strong> We believe in transparency with our users
                while respecting legal obligations. Where legally permitted, we will notify
                users of government requests for their data and publish transparency reports
                about legal requests we receive.
              </p>
            </div>
          </div>
        </section>

        {/* Contact and Legal Resources */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Legal Resources and Contact
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                For Legal Questions
              </h3>
              <p className="text-gray-600 text-sm mb-4">
                For questions about legal compliance, law enforcement requests,
                or legal interpretation of our terms:
              </p>
              <div className="bg-gray-100 p-3 rounded text-sm">
                <strong>Legal Department</strong><br />
                Email: legal@jesusisking.app<br />
                Response time: 5-10 business days
              </div>
              <p className="text-xs text-gray-500 mt-2">
                Note: We cannot provide legal advice. Consult qualified counsel for legal guidance.
              </p>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Legal Resources
              </h3>
              <ul className="space-y-2 text-sm">
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">EFF Legal Guide for Software Developers <ExternalLink className="h-3 w-3 ml-1" /></a></li>
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">Export Administration Regulations (EAR) <ExternalLink className="h-3 w-3 ml-1" /></a></li>
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">International Encryption Laws Database <ExternalLink className="h-3 w-3 ml-1" /></a></li>
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">Religious Freedom Legal Resources <ExternalLink className="h-3 w-3 ml-1" /></a></li>
                <li><Link href="/conduct" className="text-primary-600 hover:underline">Our Code of Conduct</Link></li>
              </ul>
            </div>
          </div>
        </section>

        {/* Final Disclaimer */}
        <section className="mb-16">
          <div className="danger">
            <div className="flex items-start">
              <Info className="h-6 w-6 mr-3 mt-1 flex-shrink-0" />
              <div>
                <h3 className="text-lg font-semibold mb-2">Final Legal Disclaimer</h3>
                <p className="text-sm mb-4">
                  This legal information is provided for educational purposes only and does not
                  constitute legal advice. Laws vary significantly by jurisdiction and change
                  frequently. Users must obtain qualified legal counsel for guidance specific
                  to their situation.
                </p>
                <p className="text-sm mb-4">
                  By using this platform, you acknowledge that you have read, understood, and
                  agree to comply with all applicable laws and regulations. You further acknowledge
                  that you are solely responsible for such compliance and that the platform
                  operators disclaim any liability for your legal compliance or the consequences
                  of your actions.
                </p>
                <p className="text-sm">
                  <strong>Last Updated:</strong> January 2025 •
                  <strong> Governing Law:</strong> Laws of the jurisdiction where you are located
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Scripture Closing */}
        <section>
          <div className="prayer-card text-center">
            <Book className="h-8 w-8 text-primary-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-900 mb-4">
              A Prayer for Wisdom in Legal Matters
            </h3>
            <div className="scripture-verse text-center">
              "If any of you lacks wisdom, you should ask God, who gives generously to all
              without finding fault, and it will be given to you." - James 1:5
            </div>
            <p className="text-gray-600 mt-4">
              May God grant wisdom to all who use this platform, that they may act with
              integrity, respect for authority, and love for their neighbors in all
              their communications and legal compliance.
            </p>
          </div>
        </section>
      </div>
    </Layout>
  )
}