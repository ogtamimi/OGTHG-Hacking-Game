# 🛡️ OGTHG - The Next-Gen Web CTF Platform

![Author](https://img.shields.io/badge/Created_By-OGT_(Omar_Al_Tamimi)-blue?style=for-the-badge)
![React](https://img.shields.io/badge/React-19-blue?style=for-the-badge&logo=react)
![Gemini](https://img.shields.io/badge/AI-Gemini_3_Flash-8E75B2?style=for-the-badge&logo=google-gemini)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**OGTHG (OGT Hacking Game)** is a world-class, educational playground for aspiring security researchers., it bridges the gap between theoretical security concepts and practical exploitation through high-fidelity simulations, gamified progression, and real-time AI mentorship.

---

## 📸 Screenshots

### Landing Page
![Landing Page](./public/assets/login.png)

### Challenges Dashboard
![Challenges](./public/assets/challenges.png)

### Academy Learning Platform
![Academy](./public/assets/academic.png)

---

## 🚀 Key Features

### 🖥️ High-Fidelity Simulators
- **Browser Sandbox**: A custom-built virtual browser that allows inspecting source code, manipulating cookies, and executing XSS/SQLi payloads in a safe, isolated environment.
- **Terminal Nexus**: A simulated Linux-style bash environment for practicing command injection and directory traversal.

### 🤖 AI Mentor: Operative Omar
- Integrated with **Google Gemini 3 Flash**, Omar acts as a "simple-speaking" hacker mentor.
- Provides contextual hints based on the specific challenge.
- Explains the "Why" behind vulnerabilities to ensure deep conceptual learning.

### 📚 Comprehensive Academy
- 12 detailed modules covering the full spectrum of modern web attacks, including SQLi, XSS, SSRF, JWT, and SSTI.

### 🏆 Gamified Mastery
- **Dashboard**: Track your XP, Clearance Level, and skill analysis.
- **Leaderboard**: Compete with other operatives in the Hall of Fame.

---

## 🛠️ Tech Stack

- **Framework**: [React 19](https://react.dev/)
- **Build Tool**: [Vite](https://vitejs.dev/)
- **Styling**: [Tailwind CSS](https://tailwindcss.com/)
- **Animations**: [Framer Motion](https://www.framer.com/motion/)
- **Intelligence**: [@google/genai](https://www.npmjs.com/package/@google/genai) (Gemini 3 Flash)
- **Icons**: [Lucide React](https://lucide.dev/)
- **Charts**: [Recharts](https://recharts.org/)

---

## 📁 Project Structure

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


---

## 🚀 Getting Started

### Prerequisites

- **Node.js** (v18 or higher)
- **npm** or **yarn**
- **Gemini API Key** (Get it from [Google AI Studio](https://makersuite.google.com/app/apikey))

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/ogtamimi/OGTHG-Hacking-Game.git
   cd OGTHG-Hacking-Game
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   
   Create a `.env.local` file in the root directory:
   ```env
   GEMINI_API_KEY=your_api_key_here
   ```

4. **Run the development server**
   ```bash
   npm run dev
   ```

5. **Open your browser**
   
   Navigate to `http://localhost:3000`

---

## 🏗️ Build & Deploy

### Build for Production

```bash
npm run build
```

This creates an optimized production build in the `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

### Deploy to GitHub Pages

1. **Update the base path** in `vite.config.ts` to match your repository name:
   ```typescript
   base: '/YOUR-REPO-NAME/',
   ```

2. **Deploy**
   ```bash
   npm run deploy
   ```

This will build the project and deploy it to GitHub Pages automatically.

---

## 🎮 How to Use

1. **Start Learning**: Visit the Academy to learn about web vulnerabilities
2. **Practice Challenges**: Apply your knowledge in realistic CTF scenarios
3. **Get AI Help**: Use Operative Omar for hints and explanations
4. **Track Progress**: Monitor your XP and skill development on the Dashboard
5. **Compete**: Check the Leaderboard to see how you rank

---

## 🔐 Security Features

- All exploits run in isolated sandboxes
- No actual vulnerabilities in the platform itself
- Educational content reviewed by security professionals
- Safe environment for learning offensive security

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📚 Documentation

- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [License](LICENSE)

---

## 🛡️ Security Disclaimer

This platform is intended **strictly for educational purposes**. All "exploits" are performed within a simulated sandbox environment. The goal is to train white-hat security professionals and improve the overall security posture of the web.

**Do not use the knowledge gained here for malicious purposes.**

---

## 📧 Contact & Support

- **Author**: Omar Al Tamimi (OGT)
- **Email**: [ogttamimi@gmail.com](mailto:ogttamimi@gmail.com)
- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/OGTHG-Hacking-Game/issues)

---

## 📝 License

**Version 1.1**  
Licensed under the [MIT License](LICENSE).  
© 2024-2026 OGTHG Platform. Built for the next generation of security researchers.

---

## 🌟 Acknowledgments

- Google Gemini AI for powering the AI mentor
- The cybersecurity community for inspiration
- All contributors and supporters of this project

---

<div align="center">
  <strong>Made with ❤️ by OGT (Omar Al Tamimi)</strong>
  <br>
  <em>Empowering the next generation of ethical hackers</em>
</div>
