import Layout from '../components/Layout'
import Link from 'next/link'
import {
  Scale,
  Heart,
  Shield,
  AlertTriangle,
  CheckCircle,
  Book,
  Users,
  Lock,
  ExternalLink
} from 'lucide-react'

export default function Conduct() {
  const principles = [
    {
      title: 'Honor God in All Communications',
      description: 'Use this platform in ways that glorify God and reflect His character.',
      verse: '"So whether you eat or drink or whatever you do, do it all for the glory of God." - 1 Corinthians 10:31'
    },
    {
      title: 'Speak Truth in Love',
      description: 'Communicate honestly while showing love, kindness, and respect for others.',
      verse: '"Instead, speaking the truth in love, we will grow to become in every respect the mature body of him who is the head, that is, Christ." - Ephesians 4:15'
    },
    {
      title: 'Protect the Innocent',
      description: 'Use security tools to protect those who need safety, not to harm others.',
      verse: '"Rescue the weak and the needy; deliver them from the hand of the wicked." - Psalm 82:4'
    },
    {
      title: 'Obey Lawful Authority',
      description: 'Respect and obey all applicable laws and legitimate governmental authority.',
      verse: '"Let everyone be subject to the governing authorities, for there is no authority except that which God has established." - Romans 13:1'
    },
    {
      title: 'Exercise Wisdom and Discernment',
      description: 'Use good judgment in all communications and security practices.',
      verse: '"The simple believe anything, but the prudent give thought to their steps." - Proverbs 14:15'
    },
    {
      title: 'Love Your Neighbor',
      description: 'Consider how your actions affect others and seek their good.',
      verse: '"Love your neighbor as yourself." - Mark 12:31'
    }
  ]

  const prohibitions = [
    'Illegal activities of any kind',
    'Harassment, threats, or intimidation',
    'Sharing illegal content or contraband',
    'Violating others\' privacy without consent',
    'Circumventing lawful investigations',
    'Planning or coordinating harmful activities',
    'Spreading false information or deception',
    'Using the platform for commercial spam',
    'Attempting to hack or compromise the system',
    'Sharing content that glorifies violence or hatred'
  ]

  const guidelines = [
    {
      category: 'Communication Ethics',
      items: [
        'Be honest and truthful in all communications',
        'Respect others\' dignity and privacy',
        'Use language that builds up rather than tears down',
        'Avoid gossip, slander, or spreading rumors',
        'Be slow to anger and quick to forgive'
      ]
    },
    {
      category: 'Security Best Practices',
      items: [
        'Verify the identity of communication partners',
        'Use secure passphrases and enable two-factor authentication',
        'Keep software updated and verify all downloads',
        'Be cautious about sharing sensitive information',
        'Follow operational security (OpSec) guidelines'
      ]
    },
    {
      category: 'Legal Compliance',
      items: [
        'Understand and follow all applicable local laws',
        'Respect intellectual property rights',
        'Comply with data protection regulations',
        'Report suspected illegal activity to authorities',
        'Consult legal counsel when in doubt'
      ]
    },
    {
      category: 'Faith-Based Conduct',
      items: [
        'Pray before making important decisions',
        'Seek wisdom from Scripture and trusted believers',
        'Practice forgiveness and reconciliation',
        'Use your freedom to serve others, not for selfish gain',
        'Be a witness for Christ in your conduct'
      ]
    }
  ]

  return (
    <Layout
      title="Code of Conduct"
      description="Biblical principles and guidelines for using the JESUS IS KING platform responsibly"
    >
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Scale className="h-16 w-16 text-primary-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Code of Conduct
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Guidelines for using the JESUS IS KING platform in accordance with Biblical principles,
            legal requirements, and ethical standards.
          </p>
        </div>

        {/* Core Scripture */}
        <div className="prayer-card text-center mb-12">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">
            Our Foundation
          </h2>
          <div className="scripture-verse text-center">
            "Finally, brothers and sisters, whatever is true, whatever is noble, whatever is right,
            whatever is pure, whatever is lovely, whatever is admirable—if anything is excellent
            or praiseworthy—think about such things." - Philippians 4:8
          </div>
        </div>

        {/* Legal Notice */}
        <div className="danger mb-12">
          <div className="flex items-start">
            <AlertTriangle className="h-6 w-6 mr-3 mt-1 flex-shrink-0" />
            <div>
              <h3 className="text-lg font-semibold mb-2">⚖️ LEGAL COMPLIANCE REQUIRED</h3>
              <p className="mb-4">
                <strong>This platform must be used in full compliance with all applicable laws.</strong>
                Users are responsible for understanding and following the laws in their jurisdiction.
                Illegal use is strictly prohibited and may result in legal consequences.
              </p>
              <p>
                <strong>Educational Purpose:</strong> This platform is designed for educational purposes
                and lawful communication only. Not intended for illegal activities.
              </p>
            </div>
          </div>
        </div>

        {/* Biblical Principles */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Book className="h-8 w-8 text-primary-600 mr-3" />
            Biblical Principles for Secure Communication
          </h2>

          <div className="space-y-6">
            {principles.map((principle, index) => (
              <div key={index} className="card">
                <h3 className="text-lg font-semibold text-gray-900 mb-3">
                  {principle.title}
                </h3>
                <p className="text-gray-600 mb-4">
                  {principle.description}
                </p>
                <div className="scripture-verse text-sm">
                  {principle.verse}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Prohibited Activities */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Shield className="h-8 w-8 text-red-600 mr-3" />
            Prohibited Activities
          </h2>

          <div className="card bg-red-50 border-red-200">
            <p className="text-red-700 mb-6">
              The following activities are strictly prohibited on this platform:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {prohibitions.map((item, index) => (
                <div key={index} className="flex items-start">
                  <AlertTriangle className="h-4 w-4 text-red-600 mr-2 mt-0.5 flex-shrink-0" />
                  <span className="text-red-700 text-sm">{item}</span>
                </div>
              ))}
            </div>
            <div className="mt-6 p-4 bg-red-100 rounded-lg">
              <p className="text-red-800 text-sm font-medium">
                Violation of these prohibitions may result in:
              </p>
              <ul className="text-red-700 text-sm mt-2 space-y-1">
                <li>• Immediate termination of access</li>
                <li>• Reporting to appropriate authorities</li>
                <li>• Legal prosecution to the full extent of the law</li>
                <li>• Cooperation with law enforcement investigations</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Guidelines */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <CheckCircle className="h-8 w-8 text-green-600 mr-3" />
            Positive Guidelines
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {guidelines.map((section, index) => (
              <div key={index} className="card">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                  {section.category === 'Communication Ethics' && <Heart className="h-5 w-5 text-primary-600 mr-2" />}
                  {section.category === 'Security Best Practices' && <Lock className="h-5 w-5 text-primary-600 mr-2" />}
                  {section.category === 'Legal Compliance' && <Scale className="h-5 w-5 text-primary-600 mr-2" />}
                  {section.category === 'Faith-Based Conduct' && <Book className="h-5 w-5 text-primary-600 mr-2" />}
                  {section.category}
                </h3>
                <ul className="space-y-2">
                  {section.items.map((item, itemIndex) => (
                    <li key={itemIndex} className="flex items-start">
                      <CheckCircle className="h-4 w-4 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-700 text-sm">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>

        {/* Community Standards */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Users className="h-8 w-8 text-primary-600 mr-3" />
            Community Standards
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Respect and Dignity
              </h3>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Treat all users with respect and kindness</li>
                <li>• Value diversity while maintaining Biblical truth</li>
                <li>• Practice patience and understanding</li>
                <li>• Avoid inflammatory or divisive language</li>
                <li>• Build up the community through positive interaction</li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Accountability and Growth
              </h3>
              <ul className="text-sm text-gray-600 space-y-2">
                <li>• Accept responsibility for your actions</li>
                <li>• Be open to correction and guidance</li>
                <li>• Help others learn and grow in wisdom</li>
                <li>• Practice Biblical conflict resolution</li>
                <li>• Seek reconciliation when relationships are damaged</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Reporting and Enforcement */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Reporting and Enforcement
          </h2>

          <div className="space-y-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                How to Report Violations
              </h3>
              <p className="text-gray-600 mb-4">
                If you observe violations of this code of conduct or illegal activity:
              </p>
              <ol className="text-sm text-gray-600 space-y-2">
                <li><strong>1. Document the violation</strong> - Save evidence if safe to do so</li>
                <li><strong>2. Report immediately</strong> - Contact platform administrators</li>
                <li><strong>3. Contact authorities</strong> - Report illegal activity to law enforcement</li>
                <li><strong>4. Protect yourself</strong> - Prioritize your safety and security</li>
              </ol>
            </div>

            <div className="card bg-blue-50 border-blue-200">
              <h3 className="text-lg font-semibold text-blue-800 mb-4">
                Biblical Approach to Discipline
              </h3>
              <p className="text-blue-700 text-sm mb-3">
                Our enforcement follows Biblical principles of restoration:
              </p>
              <div className="scripture-verse text-xs mb-3">
                "Brothers and sisters, if someone is caught in a sin, you who live by the Spirit
                should restore that person gently." - Galatians 6:1
              </div>
              <ul className="text-blue-700 text-sm space-y-1">
                <li>• Private correction for minor violations</li>
                <li>• Progressive discipline for repeated offenses</li>
                <li>• Immediate suspension for serious violations</li>
                <li>• Opportunity for repentance and restoration</li>
                <li>• Permanent removal only as a last resort</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Legal Disclaimers */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Legal Disclaimers and Responsibilities
          </h2>

          <div className="space-y-6">
            <div className="warning">
              <h4 className="font-semibold text-yellow-800 mb-2">User Responsibility</h4>
              <p className="text-yellow-700 text-sm">
                Users are solely responsible for their conduct and compliance with applicable laws.
                The platform providers are not responsible for user actions or the consequences thereof.
              </p>
            </div>

            <div className="info">
              <h4 className="font-semibold text-blue-800 mb-2">Educational Purpose</h4>
              <p className="text-blue-700 text-sm">
                This platform is provided for educational purposes and lawful communication only.
                It is not intended to facilitate illegal activities or circumvent lawful authority.
              </p>
            </div>

            <div className="card">
              <h4 className="font-semibold text-gray-900 mb-2">Cooperation with Authorities</h4>
              <p className="text-gray-600 text-sm">
                We reserve the right to cooperate with law enforcement and provide information
                when legally required or when we have good faith belief that illegal activity
                has occurred.
              </p>
            </div>
          </div>
        </section>

        {/* Agreement and Acceptance */}
        <section className="mb-16">
          <div className="card bg-gradient-to-br from-primary-50 to-secondary-50 border-primary-200">
            <h2 className="text-xl font-bold text-gray-900 mb-4 text-center">
              Agreement and Acceptance
            </h2>
            <p className="text-gray-700 text-center mb-6">
              By using the JESUS IS KING platform, you agree to abide by this code of conduct
              and accept full responsibility for your actions.
            </p>
            <div className="scripture-verse text-center">
              "Let your 'Yes' be 'Yes,' and your 'No,' 'No.' For whatever is more than these is from the evil one." - Matthew 5:37
            </div>
            <div className="text-center mt-6">
              <Link href="/legal" className="btn-primary">
                Read Full Legal Terms
              </Link>
            </div>
          </div>
        </section>

        {/* Related Resources */}
        <section>
          <h2 className="text-2xl font-bold text-gray-900 mb-8">
            Related Resources
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Platform Resources</h3>
              <ul className="space-y-2">
                <li><Link href="/safety" className="text-primary-600 hover:underline">Safety & Operational Security</Link></li>
                <li><Link href="/legal" className="text-primary-600 hover:underline">Legal Terms & Compliance</Link></li>
                <li><Link href="/how-to-use" className="text-primary-600 hover:underline">How to Use Guide</Link></li>
                <li><Link href="/prayer" className="text-primary-600 hover:underline">Prayer Submission</Link></li>
              </ul>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold mb-4">External Resources</h3>
              <ul className="space-y-2 text-sm">
                <li><Link href="/scripture" className="text-primary-600 hover:underline">Scripture Reading & Study</Link></li>
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">Biblical Ethics Guide <ExternalLink className="h-3 w-3 ml-1" /></a></li>
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">Legal Aid Resources <ExternalLink className="h-3 w-3 ml-1" /></a></li>
                <li><a href="#" className="text-primary-600 hover:underline flex items-center">Cybersecurity Best Practices <ExternalLink className="h-3 w-3 ml-1" /></a></li>
              </ul>
            </div>
          </div>
        </section>
      </div>
    </Layout>
  )
}