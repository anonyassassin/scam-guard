# 🛡️ Scam Guard

A full-stack web application that helps users identify and protect themselves from scams. Built with a **Next.js** frontend and an **Express.js** backend.

---

## 🚀 Tech Stack

| Layer     | Technology       |
|-----------|-----------------|
| Frontend  | Next.js (React) |
| Backend   | Express.js      |
| Runtime   | Node.js         |

---

## 📁 Project Structure

```
scam-guard/
├── backend/          # Express.js REST API
│   ├── server.js
│   └── package.json
├── frontend/         # Next.js application
│   ├── app/
│   └── package.json
├── .gitignore
├── package.json      # Root — runs both servers
└── README.md
```

---

## ⚙️ Getting Started

### Prerequisites

Make sure you have the following installed:

- [Node.js](https://nodejs.org/) (v18 or higher)
- npm (comes with Node.js)

### 1. Clone the repository

```bash
git clone https://github.com/anonyassassin/scam-guard.git
cd scam-guard
```


### 2. Install all dependencies

From the **root** folder, run:

```bash
npm run install:all
```

This installs dependencies for both the backend and frontend in one command.

---

## 🖥️ Running the App

### Development mode

```bash
npm run dev
```

This starts both servers simultaneously:

| Server   | URL                    |
|----------|------------------------|
| Frontend | http://localhost:3000  |
| Backend  | http://localhost:8000  |

### Production mode

```bash
npm start
```

---

## 📜 Available Scripts

Run these from the **root** folder:

| Command               | Description                                    |
|-----------------------|------------------------------------------------|
| `npm run install:all` | Installs dependencies for backend and frontend |
| `npm run dev`         | Starts both servers in development mode        |
| `npm start`           | Starts both servers in production mode         |

---

## 🔌 API Overview

The backend runs on `http://localhost:8000`. Below is a summary of available endpoints:

| Method | Endpoint      | Description                  |
|--------|---------------|------------------------------|
| `POST` | `/api/check`  | Submit text or URL to scan   |
| `GET`  | `/api/health` | Health check for the server  |

> Update this table as you add more routes.

---

## 🤝 Contributing

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m "add: your feature description"`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a Pull Request

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

**Your Name**
- GitHub: [@your-username](https://github.com/anonyassassin)
