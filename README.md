# SOC Triage App

A first-line SOC triage workspace that scores uploaded security logs against CISA's Federal Civilian Executive Branch (FCEB) incident response playbooks, the National Cyber Incident Scoring System (NCISS), and the Federal Incident Notification Guidelines (FING).

Public repository: [john-danko-cyber/SOC-Triage-App](https://github.com/john-danko-cyber/SOC-Triage-App)

## Summary

The app accepts real log files (Windows Security, DNS, firewall, web, and related formats), runs a deterministic TypeScript parser that counts events and applies minimum severity floors, then produces cluster scorecards with NCISS ratings, FING notification fields, playbook next steps, and CISA page citations. Code-computed floors cannot be lowered by the model: log 07 (DNS) and log 08 (firewall) score High (Orange), and log 09 (Windows Security) scores Critical (Red). The analysis step uses an LLM via the Groq API.

## My Role

I designed the triage workflow, implemented the log parser and severity floors from the CISA documents, wired the scorecard UI (light theme), and packaged the app for a free Vercel Hobby deployment that reads `GROQ_API_KEY` only from the server environment. I also wrote the local mock path used to verify floors, labels, and retry behavior without calling a live model.

## Evidence

- Deterministic floors and labels are enforced in server code, then confirmed with the official 10-sample answer key (logs 00 through 09). A 60-run matrix covers six mock modes (match, under, over, multi, benign, fail429) against those samples.
- When the model under-rates a cluster, the code raises the scorecard to the floor. When the model returns the official NCISS name "Severe," the displayed label is normalized to Critical (Red) so it matches the app's Critical floor name. Official NCISS definition quotes and citations keep the document wording.
- Playbook PDFs ship with the app and are available in the UI for the analyst. Guardrails, reporting timelines, and page citations on the scorecard come from CISA Playbooks (Nov 2021), NCISS, and FING.
- Missing mission context never lowers a rating when suspicious activity is present. The provenance string `Assumed (Conservative Default — Missing Context)` is shown when the analyst skips the pre-score questions.

This is not an official CISA product. The playbooks, NCISS, and FING documents are public CISA references used as the scoring and response authority.

## Tools Used

- TypeScript, React, and Express
- Vite
- Groq Chat Completions API (`openai/gpt-oss-120b` on the free and developer tier)
- Vercel Hobby hosting

## Deploy

1. Fork or push this repository to GitHub (this copy uses `john-danko-cyber/SOC-Triage-App`).
2. In Vercel, import the GitHub repo and sign in with GitHub if you have not already.
3. In the Vercel project settings, add an environment variable named `GROQ_API_KEY` with your Groq API key. Do not put the key in the repo, in client code, or in a commit.
4. Deploy. Vercel builds the frontend with Vite and serves the API as a serverless function (`api/[...path].ts`) with a maximum duration of 300 seconds (the Hobby default and maximum).
5. Optional: set `GROQ_MODEL` if you need to pin a different current production model. The default is `openai/gpt-oss-120b`. `llama-3.3-70b-versatile` is enterprise-only as of 16 August 2026 and is not used here.

Request bodies are capped at 4 MB to stay under Vercel's 4.5 MB Hobby limit. Analyze runs in a single request (no background work after the response), which fits serverless hosting. In-memory job polling is only reliable on a long-running local server; the UI uses the synchronous inspect and analyze routes.

## Run locally

Prerequisites: Node.js 22 or later, and npm.

1. Copy `.env.example` to `.env` and set `GROQ_API_KEY` (not required when you use the mock).
2. Install dependencies: `npm install`
3. Development (Vite middleware plus the API): `npm run dev`
4. Production-style local run: `npm run build` then `npm start`

To exercise floors and labels without a live key:

```
MOCK_GROQ=1 PORT=3250 npm start
```

In another terminal, against the official samples if they are available on disk:

```
python3 scripts/run_original60.py --port 3250 --samples /path/to/malicious-log-samples
```

The 60-run suite expects the 10 official log files and `answer_key.csv`. It talks only to the local mock.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Confirms the server is up and the CISA PDFs are present |
| POST | `/api/triage/inspect` | Deterministic parse and floor; no model call |
| POST | `/api/triage/analyze` | One model call (or mock), then floors and scorecards |
| POST | `/api/triage/jobs/inspect` | Same as inspect; returns the result in the response |
| POST | `/api/triage/jobs/analyze` | Same as analyze; waits and returns the result in the response |
| GET | `/api/triage/jobs/:jobId` | In-memory job lookup (local server only) |

Analyze JSON body: `{ "rawLogs": "...", "contextAnswers": { "missionCritical", "piiExposure", "authorizedActivity", "ictContractor", "skippedAll" }, "detectedContext": optional }`.
