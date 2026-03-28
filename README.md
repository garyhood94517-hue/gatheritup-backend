# Gatheritup Backend

Simple Node.js API for user accounts, trial management, and payments.

## Setup — Step by Step

### 1. Create Supabase account
1. Go to supabase.com and create a free account
2. Create a new project — name it "gatheritup"
3. Go to SQL Editor and paste the contents of schema.sql — click Run
4. Go to Settings → API and copy:
   - Project URL → SUPABASE_URL
   - service_role key → SUPABASE_SERVICE_KEY

### 2. Create Stripe account
1. Go to stripe.com and create an account
2. Get your Secret Key from Developers → API Keys → sk_live_...
3. Set up a webhook pointing to https://your-railway-url/api/webhook
4. Copy the webhook signing secret → STRIPE_WEBHOOK_SECRET

### 3. Deploy to Railway
1. Go to railway.app and create an account
2. Click New Project → Deploy from GitHub repo
3. Connect this repository
4. Add environment variables (Settings → Variables):
   - SUPABASE_URL
   - SUPABASE_SERVICE_KEY
   - JWT_SECRET (any long random string)
   - STRIPE_SECRET_KEY
   - STRIPE_WEBHOOK_SECRET
5. Railway will deploy automatically

### 4. Update your Netlify frontend
Once Railway gives you a URL (e.g. https://gatheritup-backend.railway.app)
update your signup.html and app to point to that URL.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/signup | Create new account |
| POST | /api/login | Login |
| GET | /api/me | Get current user |
| POST | /api/create-checkout | Start Stripe payment |
| POST | /api/webhook | Stripe webhook |
| POST | /api/trustee | Save Legacy Access settings |

## Local Development

```bash
npm install
cp .env.example .env
# Fill in your .env values
npm run dev
```
