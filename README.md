# <p align="center">🌙 Lune — Nuance Scraper</p>

<p align="center">
  <img src="https://img.shields.io/badge/Spotify-1DB954?style=for-the-badge&logo=spotify&logoColor=white" />
  <img src="https://img.shields.io/badge/Puppeteer-40B5A4?style=for-the-badge&logo=puppeteer&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" />
</p>

---

### ✨ Overview
Lune is a high-performance **Spotify Nuance Scraper** designed to extract TOTP secrets from Spotify's encrypted web-player JavaScript bundles. It automates the discovery of cryptographic keys (XOR parameters) and decodes Base32 secrets used for advanced authentication flows.

### 🛰️ Live Data Access
If you are looking for the latest extracted nuances for your own projects, use the official raw link below:

> [!IMPORTANT]
> **🔗 [Get Raw nuances.json](https://gist.githubusercontent.com/ryu7x/a622d4c1a12c36afdcf701201e9482a3/raw/9afe2c9c7d1a5eb3f7a05d0002a94f45b73682d0/nuance.json)**

---

### 🛠️ Features
- **Real-time Extraction**: Live streaming logs from the browser environment directly to your terminal.
- **Deep Scanning**: Automatically identifies target bundles among dozens of Spotify CDN scripts.
- **Crypto Analysis**: Dynamically extracts XOR `mod` and `offset` keys from obfuscated code.
- **Continuous Mode**: Can run as a persistent service, checking for updates every 6 hours.
- **Minimalist**: Styled terminal output with a sleek, futuristic aesthetic.

---

### 🚀 Getting Started

1. **Install Dependencies**
   ```bash
   npm install puppeteer
   ```

2. **Run the Scraper**
   ```bash
   # Run once and exit
   node scraper.mjs --once

   # Run as a continuous background service
   node scraper.mjs
   ```

3. **Output Structure**
   The scraper generates a `nuances.json` file in the following format:
   ```json
   [
     {
       "s": "BASE32_SECRET_STRING...",
       "v": 61
     }
   ]
   ```

---

<p align="center">
  <i>Developed for the Lune Ecosystem. Handle with care.</i>
</p>
