import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { createClient } from '@supabase/supabase-js'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import Stripe from 'stripe'
import sgMail from '@sendgrid/mail'

dotenv.config()

sgMail.setApiKey(process.env.SENDGRID_API_KEY)
const app = express()
const PORT = process.env.PORT || 3001

// ── Supabase ────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
)

// ── Stripe ──────────────────────────────────────────────────────────────────
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2026-03-25.dahlia' }) : null

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true)
    const allowed = [
      'https://steady-klepon-508c5d.netlify.app',
      'https://www.gatheritup.com',
      'https://gatheritup.com',
      'http://localhost:5173'
    ]
    if (allowed.includes(origin)) return callback(null, true)
    callback(null, true) // Allow all for now during development
  }
}))

// ── STRIPE WEBHOOK (must be before express.json) ─────────────────────────────
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature']
  let event
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (err) {
    console.error('Webhook error:', err.message)
    return res.status(400).json({ error: 'Webhook signature failed' })
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object
    const userId = session.metadata.userId
    console.log('Payment completed for user:', userId)
    await supabase.from('users').update({ status: 'paid', paid_at: new Date().toISOString() }).eq('id', userId)
  }
  res.json({ received: true })
})

// ── STRIPE WEBHOOK (must be before express.json) ─────────────────────────────
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature']
  let event
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (err) {
    console.error('Webhook error:', err.message)
    return res.status(400).json({ error: 'Webhook signature failed' })
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object
    const userId = session.metadata.userId
    await supabase.from('users').update({ status: 'paid', paid_at: new Date().toISOString() }).eq('id', userId)
  }
  res.json({ received: true })
})

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
        price: 'price_1TGTlIKwXi134vuWqJ1fNhwF',
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

// ── ADMIN ────────────────────────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const key = (req.query.key || req.headers['x-admin-key'] || '').toLowerCase()
  const adminKey = (process.env.ADMIN_KEY || '').toLowerCase()
  if (key !== adminKey) return res.status(401).json({ error: 'Unauthorized' })
  next()
}

app.get('/api/admin/users', adminAuth, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users')
    .select('id, first_name, last_name, email, phone, status, trial_end, paid_at, created_at, comm_pref, trustee_name, trustee_email, trustee_activation')
    .order('created_at', { ascending: false })
  if (error) return res.status(500).json({ error: 'Could not fetch users' })
  res.json(users)
})

// Update trustee info
app.patch('/api/admin/users/:id/trustee', adminAuth, async (req, res) => {
  const { id } = req.params
  const { trusteeName, trusteeEmail, activationMode } = req.body
  const { error } = await supabase.from('users').update({
    trustee_name: trusteeName,
    trustee_email: trusteeEmail,
    trustee_activation: activationMode
  }).eq('id', id)
  if (error) return res.status(500).json({ error: 'Could not update trustee' })
  res.json({ success: true })
})

// Change user status
app.patch('/api/admin/users/:id/status', adminAuth, async (req, res) => {
  const { id } = req.params
  const { status } = req.body
  const validStatuses = ['trial', 'grace', 'paid', 'expired', 'deactivated']
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' })
  const { error } = await supabase.from('users').update({ status }).eq('id', id)
  if (error) return res.status(500).json({ error: 'Could not update status' })
  res.json({ success: true })
})

// Extend trial
app.patch('/api/admin/users/:id/extend-trial', adminAuth, async (req, res) => {
  const { id } = req.params
  const { days } = req.body
  const { data: user } = await supabase.from('users').select('trial_end').eq('id', id).single()
  if (!user) return res.status(404).json({ error: 'User not found' })
  const newEnd = new Date(user.trial_end)
  newEnd.setDate(newEnd.getDate() + parseInt(days))
  const { error } = await supabase.from('users').update({ trial_end: newEnd.toISOString(), status: 'trial' }).eq('id', id)
  if (error) return res.status(500).json({ error: 'Could not extend trial' })
  res.json({ success: true, newTrialEnd: newEnd.toISOString() })
})

// Send password reset email
app.post('/api/admin/users/:id/reset-password', adminAuth, async (req, res) => {
  const { id } = req.params
  const { data: user } = await supabase.from('users').select('email, first_name').eq('id', id).single()
  if (!user) return res.status(404).json({ error: 'User not found' })
  
  // Generate reset token
  const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  const resetExpiry = new Date(Date.now() + 60 * 60 * 1000) // 1 hour
  
  await supabase.from('users').update({ reset_token: resetToken, reset_expiry: resetExpiry.toISOString() }).eq('id', id)
  
  const resetUrl = \`https://steady-klepon-508c5d.netlify.app/reset-password.html?token=\${resetToken}\`
  
  try {
    await sgMail.send({
      to: user.email,
      from: 'support@gatheritup.com',
      subject: 'Reset Your Gatheritup Password',
      html: \`<p>Hi \${user.first_name},</p><p>Click the link below to reset your password. This link expires in 1 hour.</p><p><a href="\${resetUrl}">Reset My Password</a></p><p>If you didn't request this, ignore this email.</p><p>— The Gatheritup Team</p>\`
    })
    res.json({ success: true })
  } catch (err) {
    console.error('Email error:', err)
    res.status(500).json({ error: 'Could not send email' })
  }
})

// Broadcast email to all users
app.post('/api/admin/broadcast', adminAuth, async (req, res) => {
  const { subject, message, statusFilter } = req.body
  if (!subject || !message) return res.status(400).json({ error: 'Subject and message required' })
  
  let query = supabase.from('users').select('email, first_name, status')
  if (statusFilter && statusFilter !== 'all') query = query.eq('status', statusFilter)
  
  const { data: users } = await query
  if (!users || users.length === 0) return res.status(400).json({ error: 'No users found' })
  
  const emails = users.map(u => ({
    to: u.email,
    from: 'support@gatheritup.com',
    subject,
    html: \`<p>Hi \${u.first_name},</p>\${message.replace(/\n/g, '<br>')}<p>— Gary<br>Gatheritup</p>\`
  }))
  
  try {
    await sgMail.send(emails)
    res.json({ success: true, sent: emails.length })
  } catch (err) {
    console.error('Broadcast error:', err)
    res.status(500).json({ error: 'Could not send emails' })
  }
})

// ── START SERVER ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Gatheritup API running on port ${PORT}`)
})
