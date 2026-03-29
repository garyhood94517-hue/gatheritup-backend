import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { createClient } from '@supabase/supabase-js'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import Stripe from 'stripe'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 3001

// ── Supabase ────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
)

// ── Stripe ──────────────────────────────────────────────────────────────────
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://steady-klepon-508c5d.netlify.app',
    'http://localhost:5173'
  ]
}))
app.use(express.json())

// ── Auth middleware ──────────────────────────────────────────────────────────
function authRequired(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Not authenticated' })
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ error: 'Invalid token' })
  }
}

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'Gatheritup API is running' })
})

// ── SIGNUP ───────────────────────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  const { firstName, lastName, email, phone, password, commPref } = req.body

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' })
  }

  // Check if email already exists
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('email', email.toLowerCase())
    .single()

  if (existing) {
    return res.status(400).json({ error: 'An account with this email already exists.' })
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 12)

  // Create user
  const trialStart = new Date()
  const trialEnd = new Date(trialStart)
  trialEnd.setDate(trialEnd.getDate() + 30)

  const { data: user, error } = await supabase
    .from('users')
    .insert({
      first_name: firstName,
      last_name: lastName,
      email: email.toLowerCase(),
      phone: phone || null,
      password_hash: hashedPassword,
      comm_pref: commPref || 'none',
      trial_start: trialStart.toISOString(),
      trial_end: trialEnd.toISOString(),
      status: 'trial', // trial | grace | paid | expired
    })
    .select()
    .single()

  if (error) {
    console.error('Signup error:', error)
    return res.status(500).json({ error: 'Could not create account. Please try again.' })
  }

  // Create JWT
  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  )

  res.json({
    token,
    user: {
      id: user.id,
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      status: user.status,
      trialEnd: user.trial_end,
    }
  })
})

// ── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' })
  }

  const { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .single()

  if (!user) {
    return res.status(401).json({ error: 'Email or password is incorrect.' })
  }

  const valid = await bcrypt.compare(password, user.password_hash)
  if (!valid) {
    return res.status(401).json({ error: 'Email or password is incorrect.' })
  }

  // Check trial status
  const now = new Date()
  const trialEnd = new Date(user.trial_end)
  let status = user.status

  if (status === 'trial' && now > trialEnd) {
    // Move to grace period
    const graceEnd = new Date(trialEnd)
    graceEnd.setDate(graceEnd.getDate() + 30)
    status = now > graceEnd ? 'expired' : 'grace'
    await supabase.from('users').update({ status }).eq('id', user.id)
  }

  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  )

  res.json({
    token,
    user: {
      id: user.id,
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      status,
      trialEnd: user.trial_end,
    }
  })
})

// ── GET CURRENT USER ─────────────────────────────────────────────────────────
app.get('/api/me', authRequired, async (req, res) => {
  const { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('id', req.user.id)
    .single()

  if (!user) return res.status(404).json({ error: 'User not found' })

  res.json({
    id: user.id,
    firstName: user.first_name,
    lastName: user.last_name,
    email: user.email,
    phone: user.phone,
    status: user.status,
    trialEnd: user.trial_end,
    commPref: user.comm_pref,
  })
})

// ── STRIPE PAYMENT ───────────────────────────────────────────────────────────
app.post('/api/create-checkout', authRequired, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'Gatheritup — Lifetime Access',
            description: 'One time payment. Keep your memories forever.',
          },
          unit_amount: 4995, // $49.95
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `https://steady-klepon-508c5d.netlify.app/?payment=success`,
      cancel_url: `https://steady-klepon-508c5d.netlify.app/?payment=cancelled`,
      metadata: { userId: req.user.id },
    })

    res.json({ url: session.url })
  } catch (err) {
    console.error('Stripe error:', err)
    res.status(500).json({ error: 'Could not create payment session.' })
  }
})

// ── STRIPE WEBHOOK ───────────────────────────────────────────────────────────
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature']
  let event

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (err) {
    return res.status(400).json({ error: 'Webhook signature failed' })
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object
    const userId = session.metadata.userId

    await supabase
      .from('users')
      .update({ status: 'paid', paid_at: new Date().toISOString() })
      .eq('id', userId)
  }

  res.json({ received: true })
})

// ── TRUSTEE / LEGACY ACCESS ──────────────────────────────────────────────────
app.post('/api/trustee', authRequired, async (req, res) => {
  const { trusteeName, trusteeEmail, activationMode } = req.body

  await supabase
    .from('users')
    .update({
      trustee_name: trusteeName,
      trustee_email: trusteeEmail,
      trustee_activation: activationMode, // 'immediate' | 'view_only' | 'inactivity' | 'manual'
    })
    .eq('id', req.user.id)

  res.json({ success: true })
})

// ── START SERVER ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Gatheritup API running on port ${PORT}`)
})
