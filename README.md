# SOC Triage App

Try the live app: [https://soc-triage-app.vercel.app](https://soc-triage-app.vercel.app)

## Summary

This web app helps a SOC analyst triage security logs. You paste in raw logs, such as Windows login events, firewall logs, DNS logs, or web logs. The app counts the evidence, groups related events, and rates the incident using CISA's National Cyber Incident Scoring System (NCISS). That is the same scoring system federal agencies use. It also lists recommended next steps from CISA's federal incident response playbooks.

## My Role

I designed the triage workflow. I built the log parser and the minimum severity rules from the CISA documents. I also built the results screen and deployed the live app. The Groq API key stays on the server and is never stored in the repo.

## Evidence

The app reads every log line and counts things like failed logins, which IPs they came from, and risky actions such as new admin accounts or cleared logs. It then groups related events and gives the incident a severity rating.

I added minimum severity rules, or safety rules, so a serious incident cannot be rated too low. For example, if the logs show root access and cleared command history, the incident is automatically rated Critical. Nothing can rate it lower than that. An AI model, through Groq, writes the explanation. Because of the safety rules, it cannot downplay a real attack. If the model rates an incident too low, the app raises the score to the minimum.

I tested the app against 10 sample logs with known correct answers to confirm the ratings came out right. The CISA playbook PDFs are included in the app, so an analyst can open them while reviewing a result. If the analyst skips the context questions, the rating is not lowered when suspicious activity is present.

This is not an official CISA product. The playbooks and the NCISS scoring system are public CISA documents used here as the scoring and response reference.

## Run locally

You need Node.js 22 or later, and npm.

1. Copy `.env.example` to `.env` and add your `GROQ_API_KEY`. This is not required if you use the local mock.
2. Run `npm install`.
3. Run `npm run dev`.

For a production-style local run, use `npm run build` and then `npm start`. To check the severity rules without a live API key, start the app with `MOCK_GROQ=1 npm start`.

## Deploy

Import this GitHub repo into Vercel. In the project settings, add an environment variable named `GROQ_API_KEY` with your Groq API key. Do not put the key in the repo, in client code, or in a commit. Then deploy.
