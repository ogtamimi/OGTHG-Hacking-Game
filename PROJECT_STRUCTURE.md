# 📁 Project Structure

This document provides a detailed overview of the OGTHG Hacking Game project structure.

```
OGTHG-Hacking-Game/
│
├── 📂 .github/
│   └── workflows/
│       └── deploy.yml              # GitHub Actions workflow for auto-deployment
│
├── 📂 public/                      # Static assets served as-is
│   └── assets/                     # Images and media files
│       ├── academic.png           # Academy page screenshot
│       ├── challenges.png         # Challenges page screenshot
│       └── login.png              # Landing page screenshot
│
├── 📂 src/                         # Source code directory
│   │
│   ├── 📂 components/              # Reusable React components
│   │   ├── BrowserSimulator.tsx   # Virtual browser for web exploitation
│   │   ├── Sidebar.tsx            # Navigation sidebar component
│   │   └── TerminalSimulator.tsx  # Virtual terminal for command injection
│   │
│   ├── 📂 pages/                   # Application pages/routes
│   │   ├── Academy.tsx            # Learning modules and tutorials
│   │   ├── ChallengePage.tsx      # Individual challenge interface
│   │   ├── ChallengesList.tsx     # All challenges overview
│   │   ├── Dashboard.tsx          # User stats and progress tracking
│   │   ├── LandingPage.tsx        # Welcome/login page
│   │   ├── Leaderboard.tsx        # Global rankings
│   │   ├── Profile.tsx            # User profile and achievements
│   │   └── Settings.tsx           # Application settings
│   │
│   ├── 📂 services/                # External API integrations
│   │   └── geminiService.ts       # Google Gemini AI service
│   │
│   ├── 📂 utils/                   # Utility functions (empty, ready for expansion)
│   │
│   ├── App.tsx                     # Main application component & routing
│   ├── constants.tsx               # Challenge data, modules, and constants
│   ├── index.tsx                   # Application entry point
│   ├── store.ts                    # Global state management (Zustand)
│   └── types.ts                    # TypeScript type definitions
│
├── 📄 .env.local                   # Environment variables (not in git)
├── 📄 .gitignore                   # Git ignore rules
├── 📄 CODE_OF_CONDUCT.md          # Community guidelines
├── 📄 CONTRIBUTING.md             # How to contribute
├── 📄 DEPLOYMENT.md               # Deployment instructions
├── 📄 LICENSE                      # MIT License
├── 📄 package.json                 # Dependencies and scripts
├── 📄 README.md                    # Project documentation
├── 📄 SECURITY.md                  # Security policy
├── 📄 tsconfig.json               # TypeScript configuration
└── 📄 vite.config.ts              # Vite build configuration
```

---

## 📋 Directory Descriptions

### `/public`
Contains static assets that are served directly without processing. Files here are accessible at the root URL.

- **`index.html`**: The main HTML template with meta tags, fonts, and the root div
- **`assets/`**: Images, screenshots, and media files

### `/src`
The heart of the application - all TypeScript/React source code.

#### `/src/components`
Reusable UI components used across multiple pages:
- **BrowserSimulator**: Simulates a web browser for XSS/SQLi challenges
- **TerminalSimulator**: Simulates a Linux terminal for command injection
- **Sidebar**: Main navigation component

#### `/src/pages`
Full-page components mapped to routes:
- **LandingPage**: Entry point with authentication
- **Dashboard**: User progress, XP, and skill analysis
- **Academy**: 12 learning modules covering web vulnerabilities
- **ChallengesList**: Browse all available CTF challenges
- **ChallengePage**: Interactive challenge interface with simulators
- **Leaderboard**: Global rankings and competition
- **Profile**: User achievements and statistics
- **Settings**: Application preferences

#### `/src/services`
External API integrations:
- **geminiService**: Handles communication with Google Gemini AI for the AI mentor feature

#### `/src/utils`
Utility functions and helpers (currently empty, ready for expansion)

### Root Configuration Files

- **`index.html`**: The main HTML template (Vite entry point)
- **`vite.config.ts`**: Vite bundler configuration with GitHub Pages base path
- **`tsconfig.json`**: TypeScript compiler options
- **`package.json`**: Project metadata, dependencies, and npm scripts

---

## 🔧 Key Files Explained

### `src/App.tsx`
The main application component that sets up:
- React Router for navigation
- Layout structure with Sidebar
- Route definitions
- Global state initialization

### `src/constants.tsx`
Contains all static data:
- Challenge definitions (12 challenges across 4 categories)
- Academy module content (SQLi, XSS, SSRF, etc.)
- Leaderboard data
- Configuration constants

### `src/store.ts`
Global state management using Zustand:
- User profile (username, XP, level)
- Challenge completion status
- Progress tracking
- Persistent storage in localStorage

### `src/types.ts`
TypeScript type definitions for:
- Challenge structure
- User profile
- Academy modules
- Leaderboard entries

---

## 🚀 Build Output

When you run `npm run build`, Vite creates a `dist/` directory:

```
dist/
├── assets/
│   ├── index-[hash].js      # Bundled JavaScript
│   ├── index-[hash].css     # Bundled CSS
│   └── [images]             # Optimized images
└── index.html               # Production HTML
```

This `dist/` folder is what gets deployed to GitHub Pages.

---

## 📦 Dependencies Overview

### Production Dependencies
- **react** & **react-dom**: UI framework
- **react-router-dom**: Client-side routing
- **@google/genai**: AI mentor integration
- **framer-motion**: Smooth animations
- **lucide-react**: Icon library
- **recharts**: Data visualization for dashboard

### Development Dependencies
- **vite**: Fast build tool and dev server
- **typescript**: Type safety
- **@vitejs/plugin-react**: React support for Vite
- **gh-pages**: GitHub Pages deployment utility

---

## 🎯 Adding New Features

### Adding a New Page
1. Create `src/pages/NewPage.tsx`
2. Add route in `src/App.tsx`
3. Add navigation link in `src/components/Sidebar.tsx`

### Adding a New Challenge
1. Add challenge object to `src/constants.tsx`
2. Update types in `src/types.ts` if needed
3. Challenge will automatically appear in the UI

### Adding a New Component
1. Create component in `src/components/`
2. Import and use in relevant pages
3. Keep components reusable and focused

---

<div align="center">
  <strong>Structure designed for scalability and maintainability</strong>
  <br>
  <em>Built by OGT (Omar Al Tamimi)</em>
</div>
