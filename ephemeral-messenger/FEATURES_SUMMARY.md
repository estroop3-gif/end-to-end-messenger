# Ephemeral Messenger - "Jesus is King" Extension

## 🎯 Project Overview

This project extends the existing secure .securedoc editor and ephemeral messaging system with a comprehensive "Jesus is King" themed platform that prioritizes privacy, security, and spiritual guidance.

## ✅ Completed Features

### 🎨 Extension 1: Theme System & Branding
- **NordPass-inspired visual design** with calm green/teal palette
- **"Jesus is King" branding** throughout the interface
- **CSS custom properties** for consistent theming
- **Responsive design** with mobile support
- **Accessibility features** including high contrast and reduced motion support

### 📖 Extension 2: Scripture Module
- **ESV integration** with proper licensing compliance (user-provided license only)
- **Public domain translations** (KJV) with offline access
- **Original languages support** (Hebrew WLC, Greek SBLGNT) - structure ready
- **Daily verse system** with rotating biblical content
- **Licensing compliance** preventing unauthorized ESV distribution

### 🔒 Extension 3: Sealed-Sender Routing
- **Opaque routing tokens** to hide recipient identity from relay
- **Cryptographically secure token generation** with 256-bit entropy
- **Message queuing system** with TTL expiration
- **Rate limiting** for token creation
- **Background cleanup** of expired tokens and messages

### 💾 Extension 4: Retention Modes & Burner Accounts
- **Four retention modes:**
  - `memory_only`: Data exists only in memory, never written to disk
  - `session_only`: Data cleared when client disconnects
  - `bounded`: Data expires after time limit (configurable)
  - `explicit_keep`: Data persists until manually deleted
- **Burner accounts** with:
  - Single-use identity stored only in locked memory
  - Ephemeral onion service with client authentication
  - TTL-based auto-destruct (1-24 hours)
  - Enhanced quotas and rate limits
  - Zero forensic traces on destruction

### 📜 Extension 5: Moral Code & Prayer System
- **Moral code of conduct page** with 8 biblical principles:
  - Truthfulness, Love & Respect, Confidentiality, Purity
  - Wisdom & Discernment, Protection of Vulnerable, Digital Stewardship, Reconciliation
- **Scripture references** for each principle with automatic loading
- **Practical guidance** for ethical digital communication
- **Enhanced prayer system** with:
  - Encrypted local storage using AES encryption
  - Prayer categories (Personal, Family, Ministry, Healing, etc.)
  - Prayer sessions with time tracking
  - Answer tracking and statistics
  - Prayer streak calculation
  - Export/import functionality for backup

## 🛠️ Technical Implementation

### Backend (Go/Rust)
- **Sealed-sender routing service** (`server/sealedSender/router.go`)
- **Retention management system** (`server/retention/modes.go`)
- **Burner account management** (`server/burner/accounts.go`)
- **Scripture module** (`client-tauri/src-tauri/src/scripture/`)
- **ESV license management** with validation and compliance

### Frontend (React/TypeScript)
- **Login/Prayer page** (`client-tauri/src/pages/LoginPrayer.tsx`)
- **Moral code page** (`client-tauri/src/pages/MoralCode.tsx`)
- **Scripture components** with translation management
- **Retention settings** with granular privacy controls
- **Prayer manager** with comprehensive tracking
- **Theme system** with CSS custom properties

### Security Features
- **No telemetry or tracking** - completely offline operation
- **Encrypted prayer storage** using AES-256
- **Memory-only mode** for maximum privacy
- **Secure token generation** using cryptographic randomness
- **Automatic data expiration** with configurable policies
- **ESV licensing compliance** preventing copyright violations

## 🔐 Privacy & Security

### Core Principles
1. **Offline-first operation** - no network calls for Scripture or prayers
2. **User-controlled data retention** - four distinct privacy modes
3. **Encrypted local storage** - all sensitive data protected
4. **Zero telemetry** - no usage data collection
5. **Burner account support** - ephemeral identities with auto-destruct
6. **Sealed-sender routing** - recipient privacy protection

### Compliance
- **ESV licensing compliance** - requires user-provided license
- **Public domain respect** - proper attribution for KJV
- **Copyright awareness** - clear licensing information
- **GDPR-friendly** - user controls all data

## 🎯 Key Features

### Spiritual Guidance
- Daily verses with biblical themes (Hope, Trust, Courage, etc.)
- Moral code with 8 principles and Scripture foundation
- Prayer tracking with categories and analytics
- Scripture study tools with offline access

### Privacy Protection
- Four retention modes from memory-only to persistent
- Burner accounts with 1-24 hour TTL
- Sealed-sender routing for recipient anonymity
- Encrypted local prayer storage

### User Experience
- NordPass-inspired clean interface
- "Jesus is King" theming throughout
- Responsive design for all devices
- Accessibility features included

## 📋 File Structure

```
ephemeral-messenger/
├── server/
│   ├── sealedSender/router.go          # Sealed-sender routing
│   ├── retention/modes.go              # Data retention management
│   └── burner/accounts.go              # Burner account system
├── client-tauri/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── LoginPrayer.tsx         # Login with prayer panel
│   │   │   └── MoralCode.tsx           # Moral conduct guidelines
│   │   ├── components/
│   │   │   ├── Scripture/              # Scripture components
│   │   │   ├── Settings/               # Retention settings
│   │   │   └── Prayer/                 # Prayer management
│   │   ├── services/
│   │   │   ├── scriptureService.ts     # Scripture API
│   │   │   └── prayerService.ts        # Prayer management
│   │   └── styles/
│   │       └── theme.css               # Complete theme system
│   └── src-tauri/src/
│       └── scripture/                  # Rust Scripture module
│           ├── mod.rs                  # Main module
│           ├── esv_manager.rs          # ESV licensing
│           └── public_domain.rs        # KJV texts
```

## 🚀 Next Steps

The core system is complete and ready for use. Optional enhancements could include:

1. **Original language text bundles** - Complete Hebrew/Greek integration
2. **Advanced Scripture search** - Cross-references and concordance
3. **Interlinear view** - Word-by-word analysis with morphology
4. **First-run security checklist** - Guided setup process
5. **Advanced prayer analytics** - Trend analysis and insights

## 🙏 Spiritual Foundation

This system is built on biblical principles of:
- **Truth and integrity** in all communications
- **Love and respect** for all users
- **Protection of the vulnerable** through strong privacy
- **Stewardship** of technology for God's glory
- **Prayer and spiritual growth** through dedicated tools

**"Jesus is King"** - This declaration serves as both the inspiration and foundation for this secure communication platform, designed to honor God while protecting His people.

---

*"Let your light shine before others, that they may see your good deeds and glorify your Father in heaven." - Matthew 5:16*