# Ecom TaskDesk — GitHub + Vercel only (no Google)

All team data is stored as `data/db.json` inside this same GitHub repo,
written by the serverless function in `api/db.js`. One shared database,
real logins, nothing else to host.

## Setup (one time, ~5 minutes)

**1. Push this folder to GitHub**
- Create a new **private** repo (e.g. `ecom-taskdesk`)
- Upload both `index.html` and the `api` folder (drag & drop works on github.com → "Add file → Upload files")

**2. Create a GitHub token (this is the "database password")**
- GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → Generate new token
- Repository access: **Only select repositories** → pick your `ecom-taskdesk` repo
- Permissions → Repository permissions → **Contents: Read and write**
- Generate, copy the token (starts with `github_pat_`)

**3. Import to Vercel**
- Vercel → Add New → Project → import the repo (framework preset: **Other**, no build settings needed)
- Before/after first deploy, go to Project → **Settings → Environment Variables** and add:
  - `GITHUB_TOKEN` = the token from step 2
  - `SECRET` = any long random text you invent (e.g. mash the keyboard, 30+ chars)
- **Redeploy** (Deployments → ⋯ → Redeploy) so the variables take effect

**4. Sign in**
- Open your Vercel URL
- Every seeded account starts with password `ChangeMe!247` and must set their own on first sign-in
- Admin: `admin@print247.us`

## Seeded accounts
admin@print247.us · design.head@print247.us · designer1/2@print247.us ·
digital.head@print247.us · dm1/2@print247.us · seo.head@print247.us ·
seo1/2@print247.us · content.head@print247.us · writer1–4@print247.us

## Notes
- The database file `data/db.json` appears in the repo automatically after the first login. Keep the repo **private** — it contains team data (passwords are salted hashes, never plain text).
- Every change writes a commit to the repo, so you also get free full history/backup of all task data.
- Optional env vars: `GH_REPO` ("owner/repo", only if data should live in a different repo), `GH_BRANCH` (default `main`), `GH_PATH` (default `data/db.json`).
