# SURFIX

# SURFIX — Commercial-Grade Lua Obfuscator & Licensing System

## Features

- **7-Layer Obfuscation**: String Table Encryption, Control Flow Flattening, Opaque Predicates, XOR Encryption, Custom VM, Anti-Tamper, Junk Code Injection
- **License Management**: HWID binding, Discord binding, expiration dates, usage limits, key_days, auth_expire
- **FFA Mode**: No license key required for open access
- **Lightning Mode**: Skip anti-debug checks for performance
- **Silent Mode**: Suppress print output for anti-cheat evasion
- **Heartbeat System**: Enforce concurrent session limits
- **Source Locker**: AES-256-GCM encryption with one-time seed, server never sees plaintext
- **Obfuscation Cache**: 8 pre-generated variants per script version, 20-80x performance improvement
- **Admin Dashboard**: Full project/key management, logs, sessions, verify queue
- **API Key Rotation**: Regenerate admin API keys
- **HTTPS Enforcement**: Production SSL requirement

## Quick Start

### Local Development
```bash
git clone https://github.com/your/surfix.git
cd surfix
npm install
cp .env.example .env
# Edit .env with your values
npm start
