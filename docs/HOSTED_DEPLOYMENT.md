# Vercel dashboard and Render API

The dashboard in `frontend/` deploys to Vercel. `render.yaml` defines a Render
Docker web service and a separate PostgreSQL database, both on the free plan.
Render's [free PostgreSQL databases expire after 30 days](https://render.com/docs/free).
Use this configuration for evaluation rather than permanent evidence storage.

The Docker image installs only `core` and `backend`. Startup migrates the database,
bootstraps roles and the administrator idempotently, and listens on Render's `PORT`.
Render's PostgreSQL connection string is normalized to the installed psycopg 3
driver for both migrations and requests. No local credentials or captured data
are included in the image.

The dashboard is deployed at
[NetSentinel dashboard](https://frontend-pi-eight-gvw406z5rs.vercel.app).
The Blueprint already allows this exact origin. Provision the backend with
[Deploy to Render](https://render.com/deploy?repo=https%3A%2F%2Fgithub.com%2Fkrishnakanoje207-debug%2Fnetsentinal-ids%2Ftree%2Fcodex%2Frender-vercel-hosting).
The dashboard still needs `VITE_API_ORIGIN` set to the resulting Render URL and a
redeploy before sign-in can reach the hosted API.

1. Deploy the Blueprint from this repository on Render with GitHub access. Set
   `NETSENTINEL_CORS_ORIGINS` to a JSON list containing the exact Vercel dashboard
   origin, such as `["https://your-dashboard.vercel.app"]`. Include only origins
   you control. The local default permits no cross-origin browser requests.
2. Check the Render service's `/api/v1/health` endpoint. Obtain the generated
   administrator password from the first startup's private Render logs. Existing
   accounts and passwords are preserved on redeploy.
3. Set Vercel's public build variable `VITE_API_ORIGIN` to the Render HTTPS origin,
   such as `https://your-api.onrender.com`, and deploy from `frontend/`. This is a
   public address, never a token, signing secret, or database URL. Set the project's
   Node version to 24.x (the local tested version).
4. Verify sign-in, alert reads, file exports, and the direct `wss://` alert stream.
   The frontend's `vercel.json` supports refreshing `/condition` and other SPA
   routes. API calls and WebSockets connect directly to Render.

The cloud database starts empty apart from roles and its administrator. Deploying
does not migrate this computer's private database or stream its captured traffic.
The Windows resident monitor, Defender snapshots and browser audit remain local.
Render runs Linux and cannot inspect the visiting user's PC or browser history.
Browser auditing is explicitly disabled in the Blueprint. The hosted This PC page
reports unavailable evidence until a separate, authorized telemetry integration
exists; a working cloud login does not prove local monitoring is running.

If Google sign-in is enabled later, add the Vercel origin to the Google OAuth
client and configure the API's existing explicit identity mappings. Password
sign-in remains available without Google configuration.
