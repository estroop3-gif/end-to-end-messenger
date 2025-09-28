import { useState, useEffect } from 'react'
import Layout from '../components/Layout'
import Link from 'next/link'
import {
  Book,
  Search,
  Heart,
  Star,
  ChevronLeft,
  ChevronRight,
  Volume2,
  Bookmark,
  Share2,
  Copy,
  ExternalLink
} from 'lucide-react'

interface ScriptureResponse {
  passages: string[]
  canonical: string
  parsed: Array<{
    book_id: string
    book_name: string
    chapter: number
    verse: number
  }>
}

export default function Scripture() {
  const [searchQuery, setSearchQuery] = useState('')
  const [currentPassage, setCurrentPassage] = useState<ScriptureResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [savedVerses, setSavedVerses] = useState<Array<{
    reference: string
    text: string
    timestamp: string
  }>>([])
  const [showSaved, setShowSaved] = useState(false)

  // Daily verse feature
  const [dailyVerse, setDailyVerse] = useState<{
    reference: string
    text: string
  } | null>(null)

  // Popular passages for quick access
  const popularPassages = [
    'Psalm 23',
    'John 3:16',
    'Philippians 4:13',
    'Romans 8:28',
    'Jeremiah 29:11',
    'Matthew 28:19-20',
    'Isaiah 40:31',
    '1 Corinthians 13:4-8',
    'Proverbs 3:5-6',
    'Ephesians 2:8-9'
  ]

  useEffect(() => {
    // Load daily verse on component mount
    loadDailyVerse()
    loadSavedVerses()
  }, [])

  const loadDailyVerse = async () => {
    // For demo purposes, use a rotating daily verse
    const dailyVerses = [
      { reference: 'Psalm 119:105', text: 'Your word is a lamp for my feet, a light on my path.' },
      { reference: 'Matthew 4:4', text: 'Jesus answered, "It is written: \'Man shall not live on bread alone, but on every word that comes from the mouth of God.\'"' },
      { reference: '2 Timothy 3:16', text: 'All Scripture is God-breathed and is useful for teaching, rebuking, correcting and training in righteousness.' },
      { reference: 'Isaiah 55:11', text: 'So is my word that goes out from my mouth: It will not return to me empty, but will accomplish what I desire and achieve the purpose for which I sent it.' },
      { reference: 'Hebrews 4:12', text: 'For the word of God is alive and active. Sharper than any double-edged sword, it penetrates even to dividing soul and spirit, joints and marrow; it judges the thoughts and attitudes of the heart.' }
    ]

    const today = new Date().getDate()
    const verseIndex = today % dailyVerses.length
    setDailyVerse(dailyVerses[verseIndex])
  }

  const loadSavedVerses = () => {
    try {
      const saved = JSON.parse(localStorage.getItem('jesusIsKingSavedVerses') || '[]')
      setSavedVerses(saved)
    } catch (error) {
      console.error('Error loading saved verses:', error)
    }
  }

  const searchScripture = async (query: string) => {
    if (!query.trim()) return

    setLoading(true)
    setError('')

    try {
      // In a real implementation, this would call the ESV API
      // For demo purposes, we'll simulate a response
      const mockResponse: ScriptureResponse = {
        passages: [
          `[1] The LORD is my shepherd, I lack nothing.
[2] He makes me lie down in green pastures,
he leads me beside quiet waters,
[3] he refreshes my soul.
He guides me along the right paths
for his name's sake.
[4] Even though I walk
through the darkest valley,
I will fear no evil,
for you are with me;
your rod and your staff,
they comfort me.
[5] You prepare a table before me
in the presence of my enemies.
You anoint my head with oil;
my cup overflows.
[6] Surely your goodness and love will follow me
all the days of my life,
and I will dwell in the house of the LORD
forever.`
        ],
        canonical: query,
        parsed: [{
          book_id: 'PSA',
          book_name: 'Psalms',
          chapter: 23,
          verse: 1
        }]
      }

      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 800))

      setCurrentPassage(mockResponse)
    } catch (err) {
      setError('Error fetching scripture. Please try again.')
      console.error('Scripture API error:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    searchScripture(searchQuery)
  }

  const saveVerse = () => {
    if (!currentPassage) return

    const verse = {
      reference: currentPassage.canonical,
      text: currentPassage.passages[0],
      timestamp: new Date().toISOString()
    }

    const existing = savedVerses.filter(v => v.reference !== verse.reference)
    const updated = [verse, ...existing]

    setSavedVerses(updated)
    localStorage.setItem('jesusIsKingSavedVerses', JSON.stringify(updated))
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const shareVerse = () => {
    if (!currentPassage) return

    const shareText = `"${currentPassage.passages[0]}" - ${currentPassage.canonical}`

    if (navigator.share) {
      navigator.share({
        title: 'Scripture Verse',
        text: shareText
      })
    } else {
      copyToClipboard(shareText)
    }
  }

  return (
    <Layout
      title="Scripture Reading"
      description="Read and study God's Word with original language support"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Book className="h-16 w-16 text-primary-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Scripture Reading
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Study God's Word with access to original Hebrew and Greek texts. All content from trusted sources.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-8">
            {/* Daily Verse */}
            {dailyVerse && (
              <div className="prayer-card">
                <div className="text-center">
                  <Star className="h-8 w-8 text-primary-600 mx-auto mb-4" />
                  <h2 className="text-xl font-semibold text-gray-900 mb-4">
                    Daily Verse
                  </h2>
                  <div className="scripture-verse text-center">
                    {dailyVerse.text}
                  </div>
                  <div className="text-sm text-gray-600 mt-3">
                    - {dailyVerse.reference}
                  </div>
                </div>
              </div>
            )}

            {/* Search */}
            <div className="card">
              <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center">
                <Search className="h-6 w-6 text-primary-600 mr-3" />
                Search Scripture
              </h2>

              <form onSubmit={handleSearch} className="mb-6">
                <div className="flex gap-3">
                  <input
                    type="text"
                    className="input flex-1"
                    placeholder="Enter book, chapter:verse (e.g., John 3:16, Psalm 23, Romans 8)"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                  <button
                    type="submit"
                    disabled={loading || !searchQuery.trim()}
                    className="btn-primary flex items-center disabled:opacity-50"
                  >
                    {loading ? (
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                    ) : (
                      <Search className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </form>

              {/* Popular Passages */}
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-3">Popular Passages:</h3>
                <div className="flex flex-wrap gap-2">
                  {popularPassages.map((passage) => (
                    <button
                      key={passage}
                      onClick={() => {
                        setSearchQuery(passage)
                        searchScripture(passage)
                      }}
                      className="text-sm bg-gray-100 hover:bg-primary-100 text-gray-700 hover:text-primary-700 px-3 py-1 rounded-full transition-colors"
                    >
                      {passage}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Error Display */}
            {error && (
              <div className="danger">
                <p>{error}</p>
              </div>
            )}

            {/* Scripture Display */}
            {currentPassage && (
              <div className="card">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-2xl font-bold text-gray-900">
                    {currentPassage.canonical}
                  </h2>
                  <div className="flex gap-2">
                    <button
                      onClick={saveVerse}
                      className="btn-outline text-sm flex items-center"
                      title="Save verse"
                    >
                      <Bookmark className="h-4 w-4 mr-1" />
                      Save
                    </button>
                    <button
                      onClick={shareVerse}
                      className="btn-outline text-sm flex items-center"
                      title="Share verse"
                    >
                      <Share2 className="h-4 w-4 mr-1" />
                      Share
                    </button>
                    <button
                      onClick={() => copyToClipboard(currentPassage.passages[0] + ' - ' + currentPassage.canonical)}
                      className="btn-outline text-sm flex items-center"
                      title="Copy to clipboard"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                <div className="prose prose-lg max-w-none">
                  <div className="scripture-verse text-left leading-relaxed text-gray-800">
                    <pre className="whitespace-pre-wrap font-sans">
                      {currentPassage.passages[0]}
                    </pre>
                  </div>
                </div>

                {/* Study Tools */}
                <div className="mt-8 pt-6 border-t border-gray-200">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Study Tools</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="info text-center">
                      <h4 className="font-medium text-blue-800 mb-2">Original Language</h4>
                      <p className="text-sm text-blue-700">
                        {currentPassage.parsed[0]?.book_name === 'Psalms' ? 'Hebrew' : 'Greek'} text available
                      </p>
                      <button className="text-blue-600 hover:underline text-xs mt-1">
                        View Original →
                      </button>
                    </div>
                    <div className="info text-center">
                      <h4 className="font-medium text-blue-800 mb-2">Commentary</h4>
                      <p className="text-sm text-blue-700">
                        Study notes and historical context
                      </p>
                      <button className="text-blue-600 hover:underline text-xs mt-1">
                        Read Commentary →
                      </button>
                    </div>
                    <div className="info text-center">
                      <h4 className="font-medium text-blue-800 mb-2">Cross References</h4>
                      <p className="text-sm text-blue-700">
                        Related passages and themes
                      </p>
                      <button className="text-blue-600 hover:underline text-xs mt-1">
                        Find References →
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Saved Verses */}
            {showSaved && savedVerses.length > 0 && (
              <div className="card">
                <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center">
                  <Bookmark className="h-6 w-6 text-primary-600 mr-3" />
                  Saved Verses
                </h2>
                <div className="space-y-4 max-h-96 overflow-y-auto">
                  {savedVerses.map((verse, index) => (
                    <div key={index} className="bg-gray-50 p-4 rounded-lg">
                      <div className="text-sm text-gray-500 mb-2">
                        {verse.reference} • Saved {new Date(verse.timestamp).toLocaleDateString()}
                      </div>
                      <div className="scripture-verse text-left text-sm">
                        {verse.text.substring(0, 200)}{verse.text.length > 200 ? '...' : ''}
                      </div>
                      <div className="flex gap-2 mt-3">
                        <button
                          onClick={() => {
                            setSearchQuery(verse.reference)
                            searchScripture(verse.reference)
                          }}
                          className="text-primary-600 hover:underline text-sm"
                        >
                          Read Full Passage
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Reading Plan */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Today's Reading Plan
              </h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Old Testament:</span>
                  <span className="text-primary-600">Genesis 1-2</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">New Testament:</span>
                  <span className="text-primary-600">Matthew 1</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Psalm:</span>
                  <span className="text-primary-600">Psalm 1</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Proverbs:</span>
                  <span className="text-primary-600">Proverbs 1:1-7</span>
                </div>
              </div>
              <button className="btn-primary w-full mt-4 text-sm">
                Follow Reading Plan
              </button>
            </div>

            {/* My Saved Verses */}
            <div className="card">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">
                  My Saved Verses
                </h3>
                <span className="text-sm text-gray-500">
                  {savedVerses.length} saved
                </span>
              </div>
              <button
                onClick={() => {
                  setShowSaved(!showSaved)
                  if (!showSaved) loadSavedVerses()
                }}
                className="btn-outline w-full text-sm"
              >
                <Bookmark className="h-4 w-4 mr-2" />
                {showSaved ? 'Hide' : 'Show'} Saved Verses
              </button>
            </div>

            {/* Prayer Integration */}
            <div className="prayer-card">
              <div className="text-center">
                <Heart className="h-6 w-6 text-primary-600 mx-auto mb-3" />
                <h3 className="text-lg font-semibold text-gray-900 mb-3">
                  Prayer & Scripture
                </h3>
                <p className="text-sm text-gray-600 mb-4">
                  Let God's Word guide your prayers and meditation.
                </p>
                <Link href="/prayer" className="btn-primary w-full text-sm">
                  Submit Prayer
                </Link>
              </div>
            </div>

            {/* Bible Resources */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Bible Resources
              </h3>
              <ul className="space-y-2 text-sm">
                <li>
                  <a href="#" className="text-primary-600 hover:underline flex items-center">
                    Hebrew/Greek Lexicon <ExternalLink className="h-3 w-3 ml-1" />
                  </a>
                </li>
                <li>
                  <a href="#" className="text-primary-600 hover:underline flex items-center">
                    Bible Concordance <ExternalLink className="h-3 w-3 ml-1" />
                  </a>
                </li>
                <li>
                  <a href="#" className="text-primary-600 hover:underline flex items-center">
                    Study Notes <ExternalLink className="h-3 w-3 ml-1" />
                  </a>
                </li>
                <li>
                  <a href="#" className="text-primary-600 hover:underline flex items-center">
                    Bible Maps <ExternalLink className="h-3 w-3 ml-1" />
                  </a>
                </li>
                <li>
                  <a href="#" className="text-primary-600 hover:underline flex items-center">
                    Reading Plans <ExternalLink className="h-3 w-3 ml-1" />
                  </a>
                </li>
              </ul>
            </div>

            {/* ESV API Attribution */}
            <div className="card bg-blue-50 border-blue-200">
              <div className="text-center">
                <p className="text-xs text-blue-700">
                  Scripture quotations are from the ESV® Bible (The Holy Bible, English Standard Version®),
                  copyright © 2001 by Crossway. Used by permission. All rights reserved.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  )
}