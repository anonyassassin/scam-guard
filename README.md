## 🛡️ Scam Guard
A full-stack web application and Chrome extension that helps users identify and protect themselves from scams. Built with a Next.js frontend, an Express.js backend, and a Chrome Extension for real-time protection.
------------------------------
## 🚀 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js (React) |
| Backend | Express.js |
| Extension | Chrome Manifest V3 |
| Runtime | Node.js |

------------------------------
## 📁 Project Structure

scam-guard/
├── backend/          # Express.js REST API
│   ├── server.js
│   └── package.json
├── frontend/         # Next.js application
│   ├── app/
│   └── package.json
├── extension/        # Chrome Extension files
│   ├── manifest.json
│   ├── background.js
│   └── blocked.html
├── .gitignore
├── package.json      # Root — runs both servers
└── README.md

------------------------------
## ⚙️ Getting Started## Prerequisites

* [Node.js](https://nodejs.org/) (v18 or higher)
* npm (comes with Node.js)

## 1. Clone & Install

git clone https://github.com
cd scam-guard
npm run install:all

## 2. Run the App

npm run dev

| Server | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend | http://localhost:8000 |

------------------------------
## 🧩 Chrome Extension Setup
The extension provides real-time protection by scanning URLs as you browse.
## Installation

   1. Open Chrome and go to chrome://extensions/.
   2. Toggle on Developer mode (top-right).
   3. Click Load unpacked.
   4. Select the extension folder in this project directory.

## Extension Logic

* Monitoring: Uses chrome.webNavigation to detect URL changes.
* Scanning: Sends URLs to http://localhost:8000/detect for verification.
* Blocking: If a scam verdict is returned, the tab is redirected to blocked.html.

------------------------------
## 🔌 API Overview

| Method | Endpoint | Description |
|---|---|---|
| POST | /api/check | Manual scan via the Frontend dashboard |
| POST | /detect | Real-time URL scan via Chrome Extension |
| GET | /api/health | Server status check |

------------------------------
## 🤝 Contributing

   1. Fork the repository.
   2. Create a feature branch: git checkout -b feature/name.
   3. Push changes and open a Pull Request.

------------------------------
## 📄 License
MIT License — free to use, modify, and distribute.
------------------------------
## 👤 Author
Anonyassassin

* GitHub: @anonyassassin


