# Indirect Prompt Injection — Live Demo

A self-contained "internal AI assistant" for a conference stage. It answers
employee questions from a small internal knowledge base. One document (an
auto-imported support ticket, **#2228**) is poisoned with hidden instructions.
When the assistant reads it — because the user asked an *innocent* question —
it obeys the attacker and leaks a confidential key from its own system prompt.

Flip **🛡️ Defenses ON** to show the OWASP AI Exchange controls neutralising the
exact same attack.

Maps to: OWASP AI Exchange **2.2.2 Indirect prompt injection**.

---

## Setup (≈5 minutes, do it before you travel)

1. **Install Ollama** → https://ollama.com/download
2. **Pull a small model** (fast, and pleasingly injectable):
   ```
   ollama pull llama3.2
   ```
3. **Run the demo** (only the Python standard library is required):
   ```
   python3 app.py
   ```
4. Open **http://localhost:8000**

That's it. No pip installs, no API keys, no internet on stage.

---

## The three moves on stage

| # | You do | Audience sees |
|---|--------|---------------|
| 1 | Defenses **OFF**. Click *"Benign: printer issue?"* | Assistant answers correctly. Trust established. |
| 2 | Click *"Trigger: summarise open tickets"* | Assistant leaks `TK-ZX44-Qh9`. The user asked nothing malicious. |
| 3 | Flip **Defenses ON**, click *Trigger* again | Same question, no leak. Either the model ignores the embedded instruction (spotlighting), or it still prints the key and the output filter redacts it (defense-in-depth). Both are flagged in green. |

There is no offline fallback: Ollama must be running, otherwise the chat shows
an "Ollama unreachable" error.

---

## Config (environment variables)

| Var | Default | Notes |
|-----|---------|-------|
| `OLLAMA_MODEL` | `llama3.2` | Any local model. `mistral`, `qwen2.5:3b` also work well. |
| `OLLAMA_NUM_CTX` | `8192` | Context window. Every `data/*.md` doc goes into the prompt, so keep this large enough. |
| `HOST` | `127.0.0.1` | |
| `PORT` | `8000` | |
| `OLLAMA_URL` | `http://localhost:11434/api/chat` | |

---

## Files

```
app.py                     the whole app (stdlib Python + embedded UI)
test_app.py                tests, no Ollama needed: python3 -m unittest
data/
  it_ticket_2201.md        benign — printer ticket (the "benign" question)
  it_ticket_2202–2227.md   benign — filler IT tickets
  it_ticket_2228.md        ⚠ POISONED — ticket #2228, carries the injection
  hr_remote_policy.md      benign — HR policy
  onboarding_checklist.md  benign — onboarding
```

Every `data/*.md` file is a document in the knowledge base. Optional front
matter sets its metadata; `trusted: false` marks it as external/untrusted:

```
---
title: Ticket #2228 — VPN reset request
source: e-mail → auto-imported to ticket system (EXTERNAL sender)
trusted: false
---
...document body...
```

In untrusted documents, the `-----` line and everything after it is the payload.
The UI renders it in the background colour (invisible); select it with the mouse
to reveal it. Add or edit files and click **↻ Reload**; no restart needed.

Everything is fictional (company "Aptum", fake e-mails, fake key). The attack
only targets this local toy app — it's an educational demonstration of a
published OWASP threat, for defenders.
