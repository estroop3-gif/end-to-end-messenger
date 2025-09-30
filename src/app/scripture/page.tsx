'use client'

import Layout from '../../components/Layout'
import { Book, Search, Star } from 'lucide-react'

export default function Scripture() {
  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Book className="h-16 w-16 text-blue-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Scripture
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Study God's Word with access to original languages and faithful translations.
            Let Scripture guide your communications and digital interactions.
          </p>
        </div>

        {/* Daily Verse */}
        <section className="mb-16">
          <div className="card bg-blue-50 border-blue-200 text-center">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">Today's Scripture</h2>
            <div className="scripture-verse text-center max-w-2xl mx-auto">
              "Trust in the Lord with all your heart and lean not on your own understanding;
              in all your ways submit to him, and he will make your paths straight."
            </div>
            <p className="text-blue-600 font-medium mt-4">Proverbs 3:5-6</p>
          </div>
        </section>

        {/* Popular Passages */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Star className="h-8 w-8 text-blue-600 mr-3" />
            Popular Passages
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              { ref: 'Psalm 23', title: 'The Lord is My Shepherd' },
              { ref: 'John 3:16', title: 'For God So Loved the World' },
              { ref: 'Romans 8:28', title: 'All Things Work Together' },
              { ref: 'Philippians 4:13', title: 'I Can Do All Things' },
              { ref: 'Jeremiah 29:11', title: 'Plans to Prosper You' },
              { ref: '1 Corinthians 13', title: 'Love Chapter' }
            ].map((passage, index) => (
              <div key={index} className="card hover:shadow-md transition-shadow cursor-pointer">
                <h3 className="font-semibold text-gray-900 mb-2">{passage.ref}</h3>
                <p className="text-gray-600 text-sm">{passage.title}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Search Section */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-gray-900 mb-8 flex items-center">
            <Search className="h-8 w-8 text-blue-600 mr-3" />
            Search Scripture
          </h2>
          <div className="card">
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Enter a verse reference or search terms
              </label>
              <div className="flex gap-4">
                <input
                  type="text"
                  placeholder="e.g., 'John 3:16' or 'love your neighbor'"
                  className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <button className="btn-primary">
                  <Search className="h-4 w-4 mr-2" />
                  Search
                </button>
              </div>
            </div>
            <p className="text-gray-600 text-sm">
              Scripture search functionality will be available in the full application.
            </p>
          </div>
        </section>

        {/* Faith & Security */}
        <section className="card bg-blue-50 border-blue-200 text-center">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">
            Scripture & Digital Security
          </h3>
          <div className="scripture-verse text-center">
            "He who dwells in the secret place of the Most High shall abide under the shadow of the Almighty."
          </div>
          <p className="text-blue-600 font-medium mt-2 mb-4">Psalm 91:1</p>
          <p className="text-gray-600">
            Just as God protects those who dwell in His secret place, we use encryption and security
            to protect our communications. Let Scripture guide both your words and your digital practices.
          </p>
        </section>
      </div>
    </Layout>
  )
}