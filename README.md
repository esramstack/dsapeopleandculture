# DSA People & Culture portal

One HTML page with two sign-ins. There's no server and no database.

## Passwords
- **Admin:** `mskadmin`, for People & Culture and management. Admins see everything.
- **Staff:** `mskstaff`, for everyone else.

You can change both in **Settings > Passwords**. Neither password is written in the file.

## What staff see
Staff see announcements, policies and the HR Agent. You decide the details:
- **Settings > What staff can see** turns whole sections on or off: Announcements, Policies, Documents, Team directory and HR Agent.
- **Individual items:** open a policy or announcement and click **Hide from staff**, or untick **Staff can see this** when you edit it.
- **Documents are hidden from staff by default.** Tick **Staff can see this** when you upload a file or add a letter, or click the people icon next to it later.
- **Settings > Preview as staff** shows the page exactly as staff will see it.

## Publishing a change
Changes you make are saved only in your browser until you publish them.
1. Open **Settings** and click **Download updated page**. You get a file called `index.html`.
2. Upload that file to your GitHub repo in place of the current `index.html`.
3. Vercel updates the site within a minute.

## Deploying for the first time
Upload `index.html` and `og.png` to the root of your GitHub repo. The `qa` folder holds the automated tests, and you don't need to upload it.

## Privacy
Everything in the file is encrypted:
- The staff password unlocks only what staff are allowed to see.
- Staff records, documents, files, and policies or announcements hidden from staff need the admin password.
- Uploaded files are stored encrypted in your browser and inside the page.

## Using the HR Agent
- Until 1 November 2026, only admins can use the HR Agent, as a preview.
- After that, staff can use it if you add an API key for staff in **Settings > HR Agent**.
- Staff could find that key, so set a monthly spending limit on it in the Anthropic Console.
