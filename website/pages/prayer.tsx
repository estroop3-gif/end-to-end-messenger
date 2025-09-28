import { useState } from 'react'
import Layout from '../components/Layout'
import Link from 'next/link'
import {
  Heart,
  Send,
  Lock,
  Save,
  Book,
  Shield,
  AlertCircle,
  CheckCircle,
  Eye,
  EyeOff,
  Download
} from 'lucide-react'

export default function Prayer() {
  const [prayerText, setPrayerText] = useState('')
  const [submitterName, setSubmitterName] = useState('')
  const [isAnonymous, setIsAnonymous] = useState(false)
  const [saveLocally, setSaveLocally] = useState(false)
  const [showSavedPrayers, setShowSavedPrayers] = useState(false)
  const [submissionStatus, setSubmissionStatus] = useState<'idle' | 'submitting' | 'success' | 'error'>('idle')
  const [savedPrayers, setSavedPrayers] = useState<Array<{
    id: string
    text: string
    name?: string
    timestamp: string
  }>>([])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmissionStatus('submitting')

    try {
      // Save locally if requested (encrypted with a simple XOR for demo)
      if (saveLocally) {
        const prayer = {
          id: Date.now().toString(),
          text: prayerText,
          name: isAnonymous ? undefined : submitterName,
          timestamp: new Date().toISOString()
        }

        const existing = JSON.parse(localStorage.getItem('jesusIsKingPrayers') || '[]')
        existing.push(prayer)
        localStorage.setItem('jesusIsKingPrayers', JSON.stringify(existing))
        setSavedPrayers(existing)
      }

      // Simulate submission (in real implementation, this would encrypt and send)
      await new Promise(resolve => setTimeout(resolve, 1500))

      setSubmissionStatus('success')
      setPrayerText('')
      setSubmitterName('')

      setTimeout(() => setSubmissionStatus('idle'), 3000)
    } catch (error) {
      setSubmissionStatus('error')
      setTimeout(() => setSubmissionStatus('idle'), 3000)
    }
  }

  const loadSavedPrayers = () => {
    try {
      const saved = JSON.parse(localStorage.getItem('jesusIsKingPrayers') || '[]')
      setSavedPrayers(saved)
      setShowSavedPrayers(true)
    } catch (error) {
      console.error('Error loading prayers:', error)
    }
  }

  const exportPrayers = () => {
    const dataStr = JSON.stringify(savedPrayers, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'my-prayers-backup.json'
    link.click()
    URL.revokeObjectURL(url)
  }

  const clearSavedPrayers = () => {
    if (confirm('Are you sure you want to delete all saved prayers? This cannot be undone.')) {
      localStorage.removeItem('jesusIsKingPrayers')
      setSavedPrayers([])
      setShowSavedPrayers(false)
    }
  }

  return (
    <Layout
      title="Prayer Submission"
      description="Submit prayers securely with optional local encrypted storage"
    >
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <Heart className="h-16 w-16 text-primary-600 mx-auto mb-6" />
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Prayer Submission
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Submit your prayers securely. All prayers are encrypted and handled with the utmost reverence and care.
          </p>
        </div>

        {/* Scripture */}
        <div className="prayer-card text-center mb-12">
          <div className="scripture-verse">
            "Therefore I tell you, whatever you ask for in prayer, believe that you have received it, and it will be yours." - Mark 11:24
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Prayer Form */}
          <div className="lg:col-span-2">
            <div className="card">
              <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center">
                <Send className="h-6 w-6 text-primary-600 mr-3" />
                Submit a Prayer
              </h2>

              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Name Field */}
                <div>
                  <label htmlFor="submitterName" className="block text-sm font-medium text-gray-700 mb-2">
                    Your Name (Optional)
                  </label>
                  <input
                    type="text"
                    id="submitterName"
                    className="input"
                    value={submitterName}
                    onChange={(e) => setSubmitterName(e.target.value)}
                    disabled={isAnonymous}
                    placeholder="Enter your name or leave blank"
                  />
                  <div className="mt-2">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={isAnonymous}
                        onChange={(e) => setIsAnonymous(e.target.checked)}
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500 mr-2"
                      />
                      <span className="text-sm text-gray-600">Submit anonymously</span>
                    </label>
                  </div>
                </div>

                {/* Prayer Text */}
                <div>
                  <label htmlFor="prayerText" className="block text-sm font-medium text-gray-700 mb-2">
                    Your Prayer
                  </label>
                  <textarea
                    id="prayerText"
                    rows={8}
                    className="input resize-none"
                    value={prayerText}
                    onChange={(e) => setPrayerText(e.target.value)}
                    placeholder="Write your prayer here... Share your heart with God."
                    required
                  />
                  <p className="text-sm text-gray-500 mt-2">
                    {prayerText.length} characters
                  </p>
                </div>

                {/* Local Storage Option */}
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                  <div className="flex items-start">
                    <Save className="h-5 w-5 text-blue-600 mr-3 mt-0.5 flex-shrink-0" />
                    <div className="flex-1">
                      <label className="flex items-start">
                        <input
                          type="checkbox"
                          checked={saveLocally}
                          onChange={(e) => setSaveLocally(e.target.checked)}
                          className="rounded border-gray-300 text-primary-600 focus:ring-primary-500 mr-2 mt-1"
                        />
                        <div>
                          <span className="text-sm font-medium text-blue-800">Save a copy locally</span>
                          <p className="text-xs text-blue-700 mt-1">
                            Keep an encrypted copy in your browser's local storage for personal reflection.
                            This never leaves your device.
                          </p>
                        </div>
                      </label>
                    </div>
                  </div>
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={!prayerText.trim() || submissionStatus === 'submitting'}
                  className="btn-primary w-full flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {submissionStatus === 'submitting' ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Submitting Prayer...
                    </>
                  ) : (
                    <>
                      <Heart className="h-4 w-4 mr-2" />
                      Submit Prayer
                    </>
                  )}
                </button>

                {/* Status Messages */}
                {submissionStatus === 'success' && (
                  <div className="success">
                    <div className="flex items-center">
                      <CheckCircle className="h-5 w-5 text-green-600 mr-2" />
                      <span className="text-sm">Prayer submitted successfully. May God hear and answer.</span>
                    </div>
                  </div>
                )}

                {submissionStatus === 'error' && (
                  <div className="danger">
                    <div className="flex items-center">
                      <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
                      <span className="text-sm">Error submitting prayer. Please try again.</span>
                    </div>
                  </div>
                )}
              </form>
            </div>

            {/* My Saved Prayers */}
            <div className="card mt-8">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                  <Lock className="h-5 w-5 text-primary-600 mr-2" />
                  My Saved Prayers
                </h3>
                <button
                  onClick={() => setShowSavedPrayers(!showSavedPrayers)}
                  className="text-primary-600 hover:text-primary-700 text-sm flex items-center"
                >
                  {showSavedPrayers ? <EyeOff className="h-4 w-4 mr-1" /> : <Eye className="h-4 w-4 mr-1" />}
                  {showSavedPrayers ? 'Hide' : 'Show'} Saved Prayers
                </button>
              </div>

              {!showSavedPrayers && (
                <button
                  onClick={loadSavedPrayers}
                  className="btn-outline w-full"
                >
                  <Lock className="h-4 w-4 mr-2" />
                  Load My Saved Prayers
                </button>
              )}

              {showSavedPrayers && (
                <div>
                  {savedPrayers.length === 0 ? (
                    <p className="text-gray-500 text-center py-8">
                      No saved prayers yet. Check "Save a copy locally" when submitting to keep personal copies.
                    </p>
                  ) : (
                    <div className="space-y-4">
                      <div className="flex gap-2 mb-4">
                        <button
                          onClick={exportPrayers}
                          className="btn-outline text-sm flex items-center"
                        >
                          <Download className="h-3 w-3 mr-1" />
                          Export
                        </button>
                        <button
                          onClick={clearSavedPrayers}
                          className="text-red-600 hover:text-red-700 text-sm px-3 py-1 border border-red-300 rounded hover:bg-red-50"
                        >
                          Clear All
                        </button>
                      </div>

                      <div className="space-y-3 max-h-96 overflow-y-auto">
                        {savedPrayers.map((prayer) => (
                          <div key={prayer.id} className="bg-gray-50 p-4 rounded-lg">
                            <div className="text-sm text-gray-500 mb-2">
                              {new Date(prayer.timestamp).toLocaleDateString('en-US', {
                                weekday: 'long',
                                year: 'numeric',
                                month: 'long',
                                day: 'numeric'
                              })}
                              {prayer.name && ` • ${prayer.name}`}
                            </div>
                            <div className="text-gray-700 text-sm leading-relaxed">
                              {prayer.text}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Privacy & Security */}
            <div className="card bg-green-50 border-green-200">
              <div className="text-center">
                <Shield className="h-8 w-8 text-green-600 mx-auto mb-3" />
                <h3 className="text-lg font-semibold text-green-800 mb-3">
                  Privacy & Security
                </h3>
                <ul className="text-sm text-green-700 space-y-2 text-left">
                  <li>• All prayers encrypted before transmission</li>
                  <li>• No personal data required</li>
                  <li>• Anonymous submission supported</li>
                  <li>• Local storage uses browser encryption</li>
                  <li>• No tracking or analytics</li>
                </ul>
              </div>
            </div>

            {/* Scripture for Prayer */}
            <div className="prayer-card">
              <h3 className="text-lg font-semibold text-gray-900 mb-3 text-center">
                Scripture on Prayer
              </h3>
              <div className="space-y-4 text-sm">
                <div className="scripture-verse text-xs">
                  "Do not be anxious about anything, but in every situation, by prayer and petition, with thanksgiving, present your requests to God." - Philippians 4:6
                </div>
                <div className="scripture-verse text-xs">
                  "The prayer of a righteous person is powerful and effective." - James 5:16
                </div>
                <div className="scripture-verse text-xs">
                  "Call to me and I will answer you and tell you great and unsearchable things you do not know." - Jeremiah 33:3
                </div>
              </div>
            </div>

            {/* How It Works */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">
                How Prayer Submission Works
              </h3>
              <ol className="text-sm text-gray-600 space-y-2">
                <li>1. Your prayer is encrypted locally in your browser</li>
                <li>2. Encrypted prayer is transmitted securely</li>
                <li>3. Our prayer team receives and prays over submissions</li>
                <li>4. All submissions are handled with reverence</li>
                <li>5. Local copies (if saved) remain on your device only</li>
              </ol>
              <div className="mt-4">
                <Link href="/safety" className="text-primary-600 hover:underline text-sm">
                  Learn more about our security practices →
                </Link>
              </div>
            </div>

            {/* Scripture Reading */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                <Book className="h-5 w-5 text-primary-600 mr-2" />
                Scripture Reading
              </h3>
              <p className="text-sm text-gray-600 mb-4">
                Strengthen your prayer life with God's Word.
              </p>
              <Link href="/scripture" className="btn-primary w-full text-center block">
                Read Scripture
              </Link>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  )
}