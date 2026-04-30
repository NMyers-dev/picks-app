# Picks-App Deployment Guide

This app now persists all data in **MongoDB Atlas** (a free hosted MongoDB
service) instead of a local JSON file. This is what fixes the "picks aren't
saving / previous picks are gone" bug — Railway containers have ephemeral
disks, so any local file gets wiped whenever the container restarts.

The app automatically picks one of two storage modes:

| Mode             | Used when                          | Persistence |
|------------------|------------------------------------|-------------|
| **MongoDB**      | `MONGODB_URI` env var is set       | Permanent   |
| **JSON file**    | `MONGODB_URI` is NOT set           | Local-dev only — wiped on Railway restarts |

So in Railway you must set `MONGODB_URI`. Locally, leave it unset and the app
will fall back to writing `data/picks.json` exactly like before.

---

## One-time setup: MongoDB Atlas free tier

1. Go to https://www.mongodb.com/cloud/atlas/register and sign up (use your
   normal email — no credit card required for the free tier).
2. After signup it asks you to create a **deployment**. Choose:
   - **M0 / Free** cluster
   - Provider: AWS (any region near your users; `us-east-1` is fine)
   - Name: `picks-app` (or whatever)
   - Click **Create**.
3. While the cluster spins up (1–2 minutes), it'll prompt you to create a
   **database user**:
   - Username: e.g. `picksapp`
   - Password: click "Autogenerate Secure Password" → **save this somewhere**
     (you'll need it in step 5).
4. Network access: it'll ask which IPs can connect.
   - Click **Add IP Address** → **Allow Access from Anywhere** (`0.0.0.0/0`).
   - This is fine because access still requires the username/password.
   - (The fancier option is whitelisting Railway's egress IPs, but they
     change, so `0.0.0.0/0` is the practical choice.)
5. Once the cluster is ready, click **Connect** → **Drivers** → **Node.js**.
   Atlas will show you a connection string that looks like:
   ```
   mongodb+srv://picksapp:<password>@picks-app.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```
   Replace `<password>` with the password you saved in step 3. **This whole
   string is your `MONGODB_URI`.**

## Set the env var on Railway

1. Open your project in Railway → click the picks-app service.
2. Go to **Variables** tab → **+ New Variable**.
3. Name: `MONGODB_URI`, Value: the connection string from step 5 above.
4. Optional but recommended: also set `JWT_SECRET` to a long random string
   (currently it's defaulting to `change-me-in-production-...`, which means
   anyone who reads your source code could forge login tokens). Generate one:
   ```
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```
5. Railway will redeploy automatically when you save the variable.

## Verify it worked

After Railway shows the new deploy as healthy, check the deploy logs. You
should see:

```
[DB] Loaded existing state from MongoDB.   (or "Seeded fresh state" on first deploy)
[DB] Ready (MongoDB).
Picks app running on http://localhost:3000
```

If you see `[DB] WARNING: MONGODB_URI not set`, the env var didn't get
applied — double-check the variable name (case-sensitive).

## Test it end-to-end

1. Register a test user on the live site.
2. In Railway, **manually restart the service** (Settings → Restart, or push
   a no-op commit).
3. Try to log in as that user. You should still be able to. **That's the
   bug fixed.**

---

## How the storage works internally

`db-adapter.js` defines a small custom adapter for `lowdb`. On startup:

1. Connect to MongoDB.
2. Read the single document `app_state.main` (containing the entire JSON
   blob — users, tournaments, picks, etc).
3. If no document exists yet, seed it with empty defaults.
4. Hand that data to lowdb as the in-memory state.

On every `db.get(...).write()` call, the adapter pushes the updated JSON
blob back to MongoDB (asynchronously, but writes are serialized so they
arrive in order). On `SIGTERM` (which Railway sends before swapping
containers), the server flushes any pending writes before exiting.

**The whole DB lives as a single document.** This was the cheapest way to
migrate without rewriting all 41 routes. It works fine up to thousands of
picks. If the app ever outgrows that, the next step is to break entities
into proper MongoDB collections — but that's a future refactor.

## Local development

Nothing changed for local dev. Just don't set `MONGODB_URI` and the app
will read/write `data/picks.json` like it always did.

## Troubleshooting

**"MongoServerSelectionError: connect ETIMEDOUT"** in Railway logs
→ Atlas IP allowlist isn't `0.0.0.0/0`. Fix it in Atlas → Network Access.

**"Authentication failed"**
→ The `<password>` in the URI is wrong, or the DB user doesn't exist.

**Want to inspect the data?**
→ In Atlas, click **Browse Collections** on your cluster. The DB is named
`picks_app` and the collection is `app_state`. There's one document with
`_id: "main"` — the entire app state lives in its `data` field.

**Want a one-time backup before deploying?**
→ The fix is non-destructive: the first deploy will seed an empty database
in Atlas (because there's nothing to migrate). All historical picks are
already gone (they were on the wiped Railway disk). Going forward, you can
download a snapshot from Atlas any time.
