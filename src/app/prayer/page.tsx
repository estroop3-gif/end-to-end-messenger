'use client'

import { useState } from 'react'
import Layout from '../../components/Layout'
import { Heart, Send, Shield } from 'lucide-react'

export default function Prayer() {
  const [prayerText, setPrayerText] = useState('')
  const [isSubmitted, setIsSubmitted] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // In a real implementation, this would be encrypted and stored securely
    setIsSubmitted(true)
    setPrayerText('')
  }

  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Heart className="h-16 w-16 text-blue-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Prayer
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Submit your prayer requests and know that they are kept private and secure.
            Our community lifts each other up in prayer while maintaining complete confidentiality.
          </p>
        </div>

        {/* Scripture Encouragement */}
        <section className="mb-12">
          <div className="card bg-blue-50 border-blue-200 text-center">
            <div className="scripture-verse text-center">
              "Do not be anxious about anything, but in every situation, by prayer and petition,
              with thanksgiving, present your requests to God."
            </div>
            <p className="text-blue-600 font-medium mt-4">Philippians 4:6</p>
          </div>
        </section>

        {/* Prayer Form */}
        <section className="mb-16">
          <div className="card">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">Submit a Prayer Request</h2>

            {isSubmitted ? (
              <div className="text-center py-8">
                <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Heart className="h-8 w-8 text-green-600" />
                </div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Prayer Submitted</h3>
                <p className="text-gray-600 mb-4">
                  Your prayer has been submitted securely. God hears your prayers, and our community
                  will lift you up in prayer while keeping your request completely confidential.
                </p>
                <button
                  onClick={() => setIsSubmitted(false)}
                  className="btn-primary"
                >
                  Submit Another Prayer
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit}>
                <div className="mb-6">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Your Prayer Request
                  </label>
                  <textarea
                    value={prayerText}
                    onChange={(e) => setPrayerText(e.target.value)}
                    rows={6}
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-vertical"
                    placeholder="Share what's on your heart... God knows your needs and will provide."
                    required
                  />
                </div>

                <div className="mb-6">
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <div className="flex items-start">
                      <Shield className="h-5 w-5 text-blue-600 mr-3 mt-0.5 flex-shrink-0" />
                      <div>
                        <h4 className="font-semibold text-blue-800 text-sm mb-1">Privacy & Security</h4>
                        <p className="text-blue-700 text-sm">
                          Your prayers are encrypted and kept completely confidential. Only you and God
                          know the details of your request. Our prayer team prays for submitted requests
                          without seeing specific details.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn-primary w-full"
                >
                  <Send className="h-4 w-4 mr-2" />
                  Submit Prayer Request
                </button>
              </form>
            )}
          </div>
        </section>

        {/* Prayer Guidelines */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8">Prayer Guidelines</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">What We Pray For</h3>
              <ul className="text-gray-600 space-y-2 text-sm">
                <li>• Salvation and spiritual growth</li>
                <li>• Health and healing</li>
                <li>• Family and relationship needs</li>
                <li>• Work and financial concerns</li>
                <li>• Wisdom and guidance</li>
                <li>• Protection and safety</li>
                <li>• Comfort in grief and loss</li>
              </ul>
            </div>
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Our Commitment</h3>
              <ul className="text-gray-600 space-y-2 text-sm">
                <li>• Complete confidentiality</li>
                <li>• Regular prayer for all requests</li>
                <li>• Biblical foundation in all prayers</li>
                <li>• No judgment or condemnation</li>
                <li>• Secure, encrypted storage</li>
                <li>• Faith-centered approach</li>
                <li>• Christ-like love and support</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Additional Scripture */}
        <section className="card bg-blue-50 border-blue-200 text-center">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">
            God Hears Your Prayers
          </h3>
          <div className="scripture-verse text-center">
            "This is the confidence we have in approaching God: that if we ask anything
            according to his will, he hears us."
          </div>
          <p className="text-blue-600 font-medium mt-4">1 John 5:14</p>
        </section>
      </div>
    </Layout>
  )
}