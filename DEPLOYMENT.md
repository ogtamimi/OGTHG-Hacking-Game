# 🚀 Deployment Guide

This guide will help you deploy the OGTHG Hacking Game to GitHub Pages.

---

## Prerequisites

- A GitHub account
- Git installed on your local machine
- Node.js (v18 or higher) installed

---

## Step 1: Prepare Your Repository

1. **Create a new repository on GitHub**
   - Go to [GitHub](https://github.com/new)
   - Name it `OGTHG-Hacking-Game` (or your preferred name)
   - Make it public
   - Don't initialize with README (we already have one)

2. **Update the base path in `vite.config.ts`**
   
   Open `vite.config.ts` and update the `base` property to match your repository name:
   ```typescript
   base: '/OGTHG-Hacking-Game/', // Change this to your repo name
   ```

---

## Step 2: Set Up Your Gemini API Key

1. **Get a Gemini API Key**
   - Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Create a new API key

2. **Add the API key to GitHub Secrets**
   - Go to your repository on GitHub
   - Click on **Settings** → **Secrets and variables** → **Actions**
   - Click **New repository secret**
   - Name: `GEMINI_API_KEY`
   - Value: Your API key
   - Click **Add secret**

---

## Step 3: Configure GitHub Pages

1. **Go to your repository settings**
   - Navigate to **Settings** → **Pages**

2. **Configure the source**
   - Under "Build and deployment"
   - Source: **GitHub Actions**

---

## Step 4: Push Your Code

1. **Initialize Git (if not already done)**
   ```bash
   git init
   ```

2. **Add your remote repository**
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/OGTHG-Hacking-Game.git
   ```

3. **Add all files**
   ```bash
   git add .
   ```

4. **Commit your changes**
   ```bash
   git commit -m "Initial commit: OGTHG Platform v1.1"
   ```

5. **Push to GitHub**
   ```bash
   git branch -M main
   git push -u origin main
   ```

---

## Step 5: Automatic Deployment

Once you push to the `main` branch, GitHub Actions will automatically:
1. Install dependencies
2. Build the project
3. Deploy to GitHub Pages

You can monitor the deployment progress:
- Go to the **Actions** tab in your repository
- Watch the "Deploy to GitHub Pages" workflow

---

## Step 6: Access Your Site

After deployment completes (usually 2-5 minutes), your site will be available at:

```
https://YOUR_USERNAME.github.io/OGTHG-Hacking-Game/
```

---

## Manual Deployment (Alternative)

If you prefer to deploy manually:

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Build the project**
   ```bash
   npm run build
   ```

3. **Deploy using gh-pages**
   ```bash
   npm run deploy
   ```

---

## Troubleshooting

### Build Fails
- Check that all dependencies are installed: `npm install`
- Verify Node.js version: `node --version` (should be v18+)
- Check the Actions logs for specific errors

### API Key Issues
- Ensure `GEMINI_API_KEY` is set in GitHub Secrets
- Verify the API key is valid and active

### 404 Errors
- Verify the `base` path in `vite.config.ts` matches your repository name
- Ensure GitHub Pages is enabled in repository settings
- Check that the deployment workflow completed successfully

### Assets Not Loading
- Verify all asset paths use relative paths
- Check that assets are in the `public/assets/` directory
- Clear browser cache and try again

---

## Updating Your Deployment

To update your deployed site:

1. Make your changes locally
2. Commit the changes:
   ```bash
   git add .
   git commit -m "Description of changes"
   ```
3. Push to GitHub:
   ```bash
   git push origin main
   ```

GitHub Actions will automatically rebuild and redeploy your site.

---

## Custom Domain (Optional)

To use a custom domain:

1. **Add a CNAME file** in the `public/` directory with your domain
2. **Configure DNS** with your domain provider:
   - Add a CNAME record pointing to `YOUR_USERNAME.github.io`
3. **Update GitHub Pages settings**:
   - Go to Settings → Pages
   - Enter your custom domain
   - Enable "Enforce HTTPS"

---

## Environment Variables for Local Development

Create a `.env.local` file in the root directory:

```env
GEMINI_API_KEY=your_api_key_here
```

This file is already in `.gitignore` and won't be committed to GitHub.

---

## Support

If you encounter issues:
- Check the [GitHub Pages documentation](https://docs.github.com/en/pages)
- Review the [Vite deployment guide](https://vitejs.dev/guide/static-deploy.html)
- Open an issue in the repository

---

<div align="center">
  <strong>Happy Deploying! 🚀</strong>
  <br>
  <em>Built by OGT (Omar Al Tamimi)</em>
</div>
