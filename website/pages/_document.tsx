import { Html, Head, Main, NextScript } from 'next/document'

export default function Document() {
  return (
    <Html lang="en">
      <Head>
        {/* Override Next.js FOUC prevention - show content immediately */}
        <style data-next-hide-fouc="false">{`
          body { display: block !important; }
          [data-next-hide-fouc] { display: none !important; }
        `}</style>

        {/* Embed critical CSS directly until Tailwind loads */}
        <style>{`
          .min-h-screen { min-height: 100vh; }
          .bg-gray-50 { background-color: #f9fafb; }
          .bg-white { background-color: #ffffff; }
          .shadow-sm { box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05); }
          .border-b { border-bottom-width: 1px; }
          .border-gray-200 { border-color: #e5e7eb; }
          .sticky { position: sticky; }
          .top-0 { top: 0px; }
          .z-50 { z-index: 50; }
          .max-w-7xl { max-width: 80rem; }
          .mx-auto { margin-left: auto; margin-right: auto; }
          .px-4 { padding-left: 1rem; padding-right: 1rem; }
          .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
          .py-20 { padding-top: 5rem; padding-bottom: 5rem; }
          .flex { display: flex; }
          .justify-between { justify-content: space-between; }
          .items-center { align-items: center; }
          .h-16 { height: 4rem; }
          .text-xl { font-size: 1.25rem; line-height: 1.75rem; }
          .font-bold { font-weight: 700; }
          .text-primary-700 { color: #15803d; }
          .bg-gradient-to-r { background-image: linear-gradient(to right, var(--tw-gradient-stops)); }
          .from-primary-600 { --tw-gradient-from: #16a34a; }
          .to-secondary-600 { --tw-gradient-to: #0d9488; }
          .text-white { color: #ffffff; }
          .text-center { text-align: center; }
          .hero-title { font-size: 4rem; font-weight: 900; text-shadow: 0 0 20px rgba(34, 197, 94, 0.5); }
          .card { background: rgba(255, 255, 255, 0.9); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 1rem; padding: 1.5rem; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); }
          .card-enhanced { background: linear-gradient(135deg, rgba(255, 255, 255, 0.9), rgba(248, 250, 252, 0.8)); backdrop-filter: blur(15px); border: 1px solid rgba(34, 197, 94, 0.1); border-radius: 1rem; padding: 1.5rem; box-shadow: 0 10px 30px rgba(34, 197, 94, 0.1), 0 0 0 1px rgba(34, 197, 94, 0.05); transform: translateY(0); transition: all 0.3s ease; }
          .card-enhanced:hover { transform: translateY(-5px); box-shadow: 0 20px 40px rgba(34, 197, 94, 0.15); }
          .btn-primary { background-color: #16a34a; color: white; padding: 0.75rem 1.5rem; border-radius: 0.5rem; font-weight: 500; transition: all 0.2s; }
          .btn-primary:hover { background-color: #15803d; }
          .btn-enhanced { border-radius: 50px; font-weight: 600; transition: all 0.3s ease; }
          .glow { box-shadow: 0 0 20px rgba(34, 197, 94, 0.3); }
          .text-glow { text-shadow: 0 0 20px rgba(34, 197, 94, 0.5); }
          .fade-in { animation: fadeIn 0.8s ease-out forwards; }
          .floating { animation: floating 3s ease-in-out infinite; }
          .pulse-green { animation: pulseGreen 2s ease-in-out infinite; }
          .gradient-text { background: linear-gradient(135deg, #16a34a, #0d9488); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
          .hero-gradient { background: linear-gradient(135deg, #16a34a 0%, #0d9488 100%); }
          .danger { background: linear-gradient(135deg, rgba(248, 113, 113, 0.1), rgba(251, 146, 60, 0.1)); border: 1px solid rgba(248, 113, 113, 0.2); border-radius: 0.75rem; padding: 1rem; }

          @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
          @keyframes floating { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-10px); } }
          @keyframes pulseGreen { 0%, 100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4); } 50% { box-shadow: 0 0 0 10px rgba(34, 197, 94, 0); } }

          .grid { display: grid; }
          .grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
          .md\\:grid-cols-2 { @media (min-width: 768px) { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
          .lg\\:grid-cols-3 { @media (min-width: 1024px) { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
          .gap-8 { gap: 2rem; }
          .mb-16 { margin-bottom: 4rem; }
          .mb-4 { margin-bottom: 1rem; }
          .text-3xl { font-size: 1.875rem; line-height: 2.25rem; }
          .text-gray-900 { color: #111827; }
          .text-gray-600 { color: #4b5563; }
          .prayer-card { background: linear-gradient(135deg, rgba(255, 255, 255, 0.95), rgba(248, 250, 252, 0.9)); backdrop-filter: blur(20px); border: 1px solid rgba(34, 197, 94, 0.2); border-radius: 1rem; padding: 2rem; box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15); }
          .fixed { position: fixed; }
          .inset-0 { top: 0; right: 0; bottom: 0; left: 0; }
          .bg-black { background-color: #000000; }
          .bg-opacity-50 { background-color: rgba(0, 0, 0, 0.5); }
          .flex-1 { flex: 1 1 0%; }
          .hidden { display: none; }
          .md\\:flex { @media (min-width: 768px) { display: flex; } }
          .space-x-8 > :not([hidden]) ~ :not([hidden]) { margin-left: 2rem; }
          .inline-flex { display: inline-flex; }
          .text-sm { font-size: 0.875rem; line-height: 1.25rem; }
          .font-medium { font-weight: 500; }
          .text-primary-600 { color: #16a34a; }
          .border-b-2 { border-bottom-width: 2px; }
          .border-primary-600 { border-color: #16a34a; }
          .transition-colors { transition-property: color, background-color, border-color; transition-duration: 150ms; }
          .duration-200 { transition-duration: 200ms; }
          .text-gray-500 { color: #6b7280; }
          .hover\\:text-gray-700:hover { color: #374151; }
          .hover\\:border-gray-300:hover { border-color: #d1d5db; }
          .border-transparent { border-color: transparent; }
          .h-4 { height: 1rem; }
          .w-4 { width: 1rem; }
          .mr-1 { margin-right: 0.25rem; }
          .h-6 { height: 1.5rem; }
          .w-6 { width: 1.5rem; }
          .hover\\:text-gray-700:hover { color: #374151; }
          .hover\\:bg-gray-100:hover { background-color: #f3f4f6; }
          .rounded-md { border-radius: 0.375rem; }
          .p-2 { padding: 0.5rem; }
          .h-8 { height: 2rem; }
          .w-8 { width: 2rem; }
          .mr-2 { margin-right: 0.5rem; }
          .p-4 { padding: 1rem; }
          .max-w-md { max-width: 28rem; }
          .w-full { width: 100%; }
          .h-12 { height: 3rem; }
          .w-12 { width: 3rem; }
          .text-lg { font-size: 1.125rem; line-height: 1.75rem; }
          .font-semibold { font-weight: 600; }
          .mb-2 { margin-bottom: 0.5rem; }
          .mb-6 { margin-bottom: 1.5rem; }
          .gap-2 { gap: 0.5rem; }
          .btn-outline { border: 2px solid #16a34a; color: #16a34a; background: transparent; padding: 0.75rem 1.5rem; border-radius: 0.5rem; font-weight: 500; transition: all 0.2s; }
          .btn-outline:hover { background-color: #16a34a; color: white; }
          .text-balance { text-wrap: balance; }
          .scale-in { animation: scaleIn 0.6s ease-out forwards; }
          @keyframes scaleIn { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
          .mb-8 { margin-bottom: 2rem; }
          .text-primary-100 { color: #dcfce7; }
          .max-w-3xl { max-width: 48rem; }
          .flex-col { flex-direction: column; }
          .sm\\:flex-row { @media (min-width: 640px) { flex-direction: row; } }
          .gap-4 { gap: 1rem; }
          .justify-center { justify-content: center; }
          .mb-12 { margin-bottom: 3rem; }
          .hover\\:bg-gray-100:hover { background-color: #f3f4f6; }
          .px-8 { padding-left: 2rem; padding-right: 2rem; }
          .py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
          .h-5 { height: 1.25rem; }
          .w-5 { width: 1.25rem; }
          .border-2 { border-width: 2px; }
          .border-white { border-color: #ffffff; }
          .hover\\:bg-white:hover { background-color: #ffffff; }
          .hover\\:text-primary-700:hover { color: #15803d; }
          .max-w-2xl { max-width: 42rem; }
          .text-left { text-align: left; }
          .items-start { align-items: flex-start; }
          .mt-0\\.5 { margin-top: 0.125rem; }
          .flex-shrink-0 { flex-shrink: 0; }
          .block { display: block; }
          .mb-1 { margin-bottom: 0.25rem; }
          .text-blue-600 { color: #2563eb; }
          .hover\\:underline:hover { text-decoration: underline; }
          .ml-1 { margin-left: 0.25rem; }
          .from-primary-50 { --tw-gradient-from: #f0fdf4; }
          .to-secondary-50 { --tw-gradient-to: #f0fdfa; }
          .bg-gradient-to-br { background-image: linear-gradient(to bottom right, var(--tw-gradient-stops)); }
          .h-16 { height: 4rem; }
          .w-16 { width: 4rem; }
          .mb-6 { margin-bottom: 1.5rem; }
          .max-w-3xl { max-width: 48rem; }
          .text-gray-700 { color: #374151; }
          .space-y-1 > :not([hidden]) ~ :not([hidden]) { margin-top: 0.25rem; }
          .text-xs { font-size: 0.75rem; line-height: 1rem; }
          .rounded { border-radius: 0.25rem; }
          .mt-4 { margin-top: 1rem; }
          .bg-red-600 { background-color: #dc2626; }
          .hover\\:bg-red-700:hover { background-color: #b91c1c; }
          .text-red-600 { color: #dc2626; }
          .text-red-800 { color: #991b1b; }
          .text-red-700 { color: #b91c1c; }
          .bg-red-100 { background-color: #fee2e2; }
          .rounded-lg { border-radius: 0.5rem; }
          .from-red-50 { --tw-gradient-from: #fef2f2; }
          .to-orange-50 { --tw-gradient-to: #fff7ed; }
          .border-red-200 { border-color: #fecaca; }
          .text-green-500 { color: #22c55e; }
          .mr-3 { margin-right: 0.75rem; }
          .space-y-3 > :not([hidden]) ~ :not([hidden]) { margin-top: 0.75rem; }
          .mt-8 { margin-top: 2rem; }
          .ml-2 { margin-left: 0.5rem; }
          .lg\\:grid-cols-2 { @media (min-width: 1024px) { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
          .gap-12 { gap: 3rem; }
          .md\\:grid-cols-3 { @media (min-width: 768px) { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
          .bg-primary-600 { background-color: #16a34a; }
          .rounded-full { border-radius: 9999px; }
          .w-10 { width: 2.5rem; }
          .h-10 { height: 2.5rem; }
          .text-primary-600 { color: #16a34a; }
          .hover\\:text-primary-600:hover { color: #16a34a; }
          .border-t { border-top-width: 1px; }
          .mt-16 { margin-top: 4rem; }
          .py-12 { padding-top: 3rem; padding-bottom: 3rem; }
          .md\\:grid-cols-4 { @media (min-width: 768px) { grid-template-columns: repeat(4, minmax(0, 1fr)); } }
          .col-span-1 { grid-column: span 1 / span 1; }
          .md\\:col-span-2 { @media (min-width: 768px) { grid-column: span 2 / span 2; } }
          .space-y-2 > :not([hidden]) ~ :not([hidden]) { margin-top: 0.5rem; }
          .tracking-wider { letter-spacing: 0.05em; }
          .uppercase { text-transform: uppercase; }
          .pt-8 { padding-top: 2rem; }
          .md\\:flex-row { @media (min-width: 768px) { flex-direction: row; } }
          .justify-between { justify-content: space-between; }
          .text-gray-500 { color: #6b7280; }
          .md\\:mt-0 { @media (min-width: 768px) { margin-top: 0px; } }
          .warning { background: linear-gradient(135deg, rgba(251, 191, 36, 0.1), rgba(245, 158, 11, 0.1)); border: 1px solid rgba(251, 191, 36, 0.2); }
          .bg-primary-100 { background-color: #dcfce7; }
          .rounded-lg { border-radius: 0.5rem; }
          .justify-center { justify-content: center; }
          .mx-auto { margin-left: auto; margin-right: auto; }
          .mb-4 { margin-bottom: 1rem; }
          .h-6 { height: 1.5rem; }
          .w-6 { width: 1.5rem; }
          .text-primary-600 { color: #16a34a; }
          .sm\\:px-6 { @media (min-width: 640px) { padding-left: 1.5rem; padding-right: 1.5rem; } }
          .lg\\:px-8 { @media (min-width: 1024px) { padding-left: 2rem; padding-right: 2rem; } }
          .md\\:ml-6 { @media (min-width: 768px) { margin-left: 1.5rem; } }
          .md\\:space-x-8 > :not([hidden]) ~ :not([hidden]) { @media (min-width: 768px) { margin-left: 2rem; } }
          .px-1 { padding-left: 0.25rem; padding-right: 0.25rem; }
          .pt-1 { padding-top: 0.25rem; }
          .md\\:hidden { @media (min-width: 768px) { display: none; } }
          .inline { display: inline; }
          .scripture-verse { font-style: italic; color: #374151; background: linear-gradient(135deg, rgba(34, 197, 94, 0.05), rgba(13, 148, 136, 0.05)); padding: 1rem; border-radius: 0.5rem; border-left: 4px solid #16a34a; }
        `}</style>
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  )
}