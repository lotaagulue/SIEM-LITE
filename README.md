# 🛡️ SIEM Lite - Security Event Logger & Monitoring System

A lightweight, real-time Security Information and Event Management (SIEM) system built with Python, React, Supabase, and deployable to Vercel.

## 🌟 Features

- **Real-time Log Monitoring**: Live dashboard with WebSocket updates via Supabase
- **Intelligent Threat Detection**: Pattern-based anomaly detection for common attacks
- **Alert Management**: Configurable alert rules with severity levels
- **Threat Intelligence**: IP-based threat tracking and scoring
- **Analytics Dashboard**: Real-time statistics and event visualization
- **Cyberpunk UI**: Distinctive terminal-inspired interface
- **Scalable Architecture**: Serverless deployment on Vercel with Supabase PostgreSQL

## 🚀 Quick Start

### 1. Set Up Supabase

1. Create account at [supabase.com](https://supabase.com)
2. Create new project
3. Run `supabase/schema.sql` in SQL Editor
4. Copy Project URL and anon key from Settings → API

### 2. Local Development
```bash
# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Add your Supabase credentials to .env
# Then start dev server
npm run dev
```

### 3. Deploy to Vercel
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Add environment variables in Vercel dashboard:
# - SUPABASE_URL
# - SUPABASE_ANON_KEY
# - SUPABASE_SERVICE_ROLE_KEY (Required for log ingestion)
# - VITE_SUPABASE_URL
# - VITE_SUPABASE_ANON_KEY

# Deploy to production
vercel --prod
```

### 4. Test the System
```bash
# Update API_ENDPOINT in test_log_sender.py to your Vercel URL
python3 test_log_sender.py
```

## 📡 API Endpoints

### POST `/api/ingest`

Ingest a new security event.

**Request:**
```json
{
  "source": "web_server",
  "severity": "high",
  "event_type": "failed_login",
  "message": "Failed login attempt",
  "source_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "username": "admin"
}
```

**Response:**
```json
{
  "success": true,
  "event_id": "uuid-here",
  "analysis": {
    "is_anomaly": true,
    "anomaly_score": 0.75
  }
}
```

## 🔍 Threat Detection

Automatically detects:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Brute Force Attacks
- Suspicious User Agents

## 📊 Tech Stack

- **Frontend**: React 18 + Vite + Tailwind CSS
- **Backend**: Python Serverless Functions
- **Database**: PostgreSQL (Supabase)
- **Hosting**: Vercel
- **Real-time**: Supabase Realtime

## 📚 Documentation

See full documentation in the project files.

## 📄 License

MIT License

---

**Built for cybersecurity professionals** | **Production ready**