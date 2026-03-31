import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { createClient } from '@supabase/supabase-js'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import Stripe from 'stripe'
import sgMail from '@sendgrid/mail'
import { v2 as cloudinary } from 'cloudinary'
import multer from 'multer'
import { Readable } from 'stream'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 3001

sgMail.setApiKey(process.env.SENDGRID_API_KEY)

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
})

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } })

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
)

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2026-03-25.dahlia' })
  : null

app.use(cors({
  origin: [
    'https://gatheritup.com',
    'https://www.gatheritup.com',
    'https://steady-klepon-508c5d.netlify.app',
    'http://localhost:5173'
  ]
}))

// ── STRIPE WEBHOOK (must be before express.json) ──────────────────────────────
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

// ── Auth middleware ───────────────────────────────────────────────────────────
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

// ── Admin auth ────────────────────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const key = (req.query.key || req.headers['x-admin-key'] || '').toLowerCase()
  const adminKey = (process.env.ADMIN_KEY || '').toLowerCase()
  if (key !== adminKey) return res.status(401).json({ error: 'Unauthorized' })
  next()
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'Gatheritup API is running' })
})

// ── SIGNUP ────────────────────────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  const { firstName, lastName, email, phone, password, commPref } = req.body
  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' })
  }
  const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single()
  if (existing) return res.status(400).json({ error: 'An account with this email already exists.' })
  const hashedPassword = await bcrypt.hash(password, 12)
  const trialStart = new Date()
  const trialEnd = new Date(trialStart)
  trialEnd.setDate(trialEnd.getDate() + 30)
  const { data: user, error } = await supabase.from('users').insert({
    first_name: firstName, last_name: lastName, email: email.toLowerCase(),
    phone: phone || null, password_hash: hashedPassword, comm_pref: commPref || 'none',
    trial_start: trialStart.toISOString(), trial_end: trialEnd.toISOString(), status: 'trial',
  }).select().single()
  if (error) { console.error('Signup error:', error); return res.status(500).json({ error: 'Could not create account.' }) }
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '30d' })
  res.json({ token, user: { id: user.id, firstName: user.first_name, lastName: user.last_name, email: user.email, status: user.status, trialEnd: user.trial_end } })
})

// ── LOGIN ─────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' })
  const { data: user } = await supabase.from('users').select('*').eq('email', email.toLowerCase()).single()
  if (!user) return res.status(401).json({ error: 'Email or password is incorrect.' })
  const valid = await bcrypt.compare(password, user.password_hash)
  if (!valid) return res.status(401).json({ error: 'Email or password is incorrect.' })
  const now = new Date()
  const trialEnd = new Date(user.trial_end)
  let status = user.status
  if (status === 'trial' && now > trialEnd) {
    const graceEnd = new Date(trialEnd)
    graceEnd.setDate(graceEnd.getDate() + 30)
    status = now > graceEnd ? 'expired' : 'grace'
    await supabase.from('users').update({ status }).eq('id', user.id)
  }
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '30d' })
  res.json({ token, user: { id: user.id, firstName: user.first_name, lastName: user.last_name, email: user.email, status, trialEnd: user.trial_end } })
})

// ── GET CURRENT USER ──────────────────────────────────────────────────────────
app.get('/api/me', authRequired, async (req, res) => {
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single()
  if (!user) return res.status(404).json({ error: 'User not found' })
  res.json({ id: user.id, firstName: user.first_name, lastName: user.last_name, email: user.email, phone: user.phone, status: user.status, trialEnd: user.trial_end, commPref: user.comm_pref })
})

// ── STRIPE PAYMENT ────────────────────────────────────────────────────────────
app.post('/api/create-checkout', authRequired, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price: 'price_1TGTlIKwXi134vuWqJ1fNhwF', quantity: 1 }],
      mode: 'payment',
      success_url: 'https://steady-klepon-508c5d.netlify.app/?payment=success',
      cancel_url: 'https://steady-klepon-508c5d.netlify.app/?payment=cancelled',
      metadata: { userId: req.user.id },
    })
    res.json({ url: session.url })
  } catch (err) {
    console.error('Stripe error:', err)
    res.status(500).json({ error: 'Could not create payment session.' })
  }
})

// ── TRUSTEE / LEGACY ACCESS ───────────────────────────────────────────────────
app.post('/api/trustee', authRequired, async (req, res) => {
  const { trusteeName, trusteeEmail, activationMode } = req.body
  await supabase.from('users').update({ trustee_name: trusteeName, trustee_email: trusteeEmail, trustee_activation: activationMode }).eq('id', req.user.id)
  res.json({ success: true })
})

// ── SHARE: Upload media and create share link ─────────────────────────────────
app.post('/api/share', authRequired, upload.single('media'), async (req, res) => {
  try {
    const { title, story, date, isVideo } = req.body
    const { data: user } = await supabase.from('users').select('first_name, last_name, first_share_sent').eq('id', req.user.id).single()

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          resource_type: isVideo === 'true' ? 'video' : 'image',
          folder: 'gatheritup',
        },
        (error, result) => {
          if (error) reject(error)
          else resolve(result)
        }
      )
      Readable.from(req.file.buffer).pipe(stream)
    })

    // Generate share token and expiry (30 days)
    const shareToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
    const expiresAt = new Date()
    expiresAt.setDate(expiresAt.getDate() + 30)

    // Save share record to Supabase
    const { error: shareError } = await supabase.from('shares').insert({
      user_id: req.user.id,
      token: shareToken,
      media_url: uploadResult.secure_url,
      media_type: isVideo === 'true' ? 'video' : 'image',
      title: title || '',
      story: story || '',
      memory_date: date || null,
      sharer_name: user.first_name + ' ' + user.last_name,
      expires_at: expiresAt.toISOString(),
    })

    if (shareError) {
      console.error('Share save error:', shareError)
      return res.status(500).json({ error: 'Could not save share.' })
    }

    // Track first share for marketing message
    const isFirstShare = !user.first_share_sent
    if (isFirstShare) {
      await supabase.from('users').update({ first_share_sent: true }).eq('id', req.user.id)
    }

    const shareUrl = process.env.BACKEND_URL + '/share/' + shareToken

    res.json({ shareUrl, shareToken, expiresAt: expiresAt.toISOString(), isFirstShare })
  } catch (err) {
    console.error('Share error:', err)
    res.status(500).json({ error: 'Could not create share link.' })
  }
})

// ── SHARE: View shared memory page ───────────────────────────────────────────
app.get('/share/:token', async (req, res) => {
  const { token } = req.params
  const { data: share } = await supabase.from('shares').select('*').eq('token', token).single()

  if (!share) {
    return res.status(404).send(`
      <html><body style="font-family:Georgia,serif;text-align:center;padding:60px;background:#fdf6ee;">
      <h2>Memory Not Found</h2>
      <p>This memory link may have expired or been removed.</p>
      </body></html>
    `)
  }

  const now = new Date()
  const expires = new Date(share.expires_at)
  if (now > expires) {
    return res.status(410).send(`
      <html><body style="font-family:Georgia,serif;text-align:center;padding:60px;background:#fdf6ee;">
      <h2>This Memory Has Expired</h2>
      <p>This shared memory was available for 30 days and has now expired.</p>
      <p>Ask your family member to share it again from Gatheritup.</p>
      </body></html>
    `)
  }

  const isVideo = share.media_type === 'video'
  const formattedDate = share.memory_date ? new Date(share.memory_date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : ''
  const expiresFormatted = expires.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${share.sharer_name} shared a memory with you</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Georgia, serif; background: #fdf6ee; color: #333; }
    .container { max-width: 680px; margin: 0 auto; padding: 40px 20px; }
    .header { text-align: center; margin-bottom: 30px; }
    .header h1 { font-size: 26px; color: #5a3e2b; margin-bottom: 8px; }
    .header p { font-size: 18px; color: #7a5c42; }
    .media-wrap { text-align: center; margin: 30px 0; }
    .media-wrap img { max-width: 100%; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); }
    .media-wrap video { max-width: 100%; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); }
    .video-hint { font-size: 16px; color: #7a5c42; margin-top: 10px; }
    .memory-info { background: #fff8f0; border-radius: 12px; padding: 30px; margin: 20px 0; }
    .memory-title { font-size: 24px; font-weight: bold; color: #5a3e2b; margin-bottom: 8px; }
    .memory-date { font-size: 16px; color: #999; margin-bottom: 16px; }
    .memory-story { font-size: 18px; line-height: 1.7; color: #444; }
    .download-btn { display: block; width: 100%; padding: 18px; background: #5a3e2b; color: #fff; font-size: 20px; font-family: Georgia, serif; border: none; border-radius: 10px; cursor: pointer; text-align: center; text-decoration: none; margin: 20px 0; }
    .download-btn:hover { background: #7a5c42; }
    .expiry { text-align: center; font-size: 15px; color: #aaa; margin: 10px 0; }
    .marketing { background: #fff; border: 2px solid #e8d5c0; border-radius: 12px; padding: 24px; margin: 30px 0; text-align: center; }
    .marketing p { font-size: 17px; color: #5a3e2b; line-height: 1.6; margin-bottom: 14px; }
    .marketing a { display: inline-block; padding: 14px 28px; background: #e07b39; color: #fff; border-radius: 8px; text-decoration: none; font-size: 17px; }
    .marketing a:hover { background: #c9652a; }
    .footer { text-align: center; font-size: 14px; color: #bbb; margin-top: 40px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>💛 ${share.sharer_name} shared a memory with you</h1>
      ${isVideo ? '<p class="video-hint">Press play to watch this memory. Make sure your sound is on! 🔊</p>' : ''}
    </div>

    <div class="media-wrap">
      ${isVideo
        ? `<video controls playsinline><source src="${share.media_url}"></video>`
        : `<img src="${share.media_url}" alt="${share.title}">`
      }
    </div>

    <div class="memory-info">
      ${share.title ? `<div class="memory-title">${share.title}</div>` : ''}
      ${formattedDate ? `<div class="memory-date">${formattedDate}</div>` : ''}
      ${share.story ? `<div class="memory-story">${share.story}</div>` : ''}
    </div>

    <a class="download-btn" href="${share.media_url}" download>
      💾 Download This Memory — Save It to Your Device
    </a>

    <p class="expiry">This memory was shared with love and will be available until ${expiresFormatted}.</p>

    <div class="marketing">
      <p>Enjoyed this memory? Gatheritup helps families preserve their photos, videos, and the stories behind them — all in one beautiful place.</p>
      <p><strong>Try it free for 30 days — no credit card needed.</strong></p>
      <a href="https://gatheritup.com/signup.html">Start My Free Trial at Gatheritup.com</a>
    </div>

    <div class="footer">
      Shared with love using <a href="https://gatheritup.com" style="color:#bbb;">Gatheritup.com</a> — where families preserve their memories.
    </div>
  </div>
</body>
</html>
  `)
})

// ── ADMIN ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users')
    .select('id, first_name, last_name, email, phone, status, trial_end, paid_at, created_at, comm_pref, trustee_name, trustee_email, trustee_activation')
    .order('created_at', { ascending: false })
  if (error) return res.status(500).json({ error: 'Could not fetch users' })
  res.json(users)
})

app.patch('/api/admin/users/:id/trustee', adminAuth, async (req, res) => {
  const { id } = req.params
  const { trusteeName, trusteeEmail, activationMode } = req.body
  const { error } = await supabase.from('users').update({ trustee_name: trusteeName, trustee_email: trusteeEmail, trustee_activation: activationMode }).eq('id', id)
  if (error) return res.status(500).json({ error: 'Could not update trustee' })
  res.json({ success: true })
})

app.patch('/api/admin/users/:id/status', adminAuth, async (req, res) => {
  const { id } = req.params
  const { status } = req.body
  const validStatuses = ['trial', 'grace', 'paid', 'expired', 'deactivated']
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' })
  const { error } = await supabase.from('users').update({ status }).eq('id', id)
  if (error) return res.status(500).json({ error: 'Could not update status' })
  res.json({ success: true })
})

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

app.post('/api/admin/users/:id/reset-password', adminAuth, async (req, res) => {
  const { id } = req.params
  const { data: user } = await supabase.from('users').select('email, first_name').eq('id', id).single()
  if (!user) return res.status(404).json({ error: 'User not found' })
  const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  const resetExpiry = new Date(Date.now() + 60 * 60 * 1000)
  await supabase.from('users').update({ reset_token: resetToken, reset_expiry: resetExpiry.toISOString() }).eq('id', id)
  const resetUrl = 'https://steady-klepon-508c5d.netlify.app/reset-password.html?token=' + resetToken
  try {
    await sgMail.send({
      to: user.email,
      from: 'support@gatheritup.com',
      subject: 'Reset Your Gatheritup Password',
      html: '<p>Hi ' + user.first_name + ',</p><p>Click below to reset your password. This link expires in 1 hour.</p><p><a href="' + resetUrl + '">Reset My Password</a></p><p>If you did not request this, ignore this email.</p><p>— The Gatheritup Team</p>'
    })
    res.json({ success: true })
  } catch (err) {
    console.error('Email error:', err)
    res.status(500).json({ error: 'Could not send email' })
  }
})

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
    subject: subject,
    html: '<p>Hi ' + u.first_name + ',</p>' + message.replace(/\n/g, '<br>') + '<p>— Gary<br>Gatheritup</p>'
  }))
  try {
    await sgMail.send(emails)
    res.json({ success: true, sent: emails.length })
  } catch (err) {
    console.error('Broadcast error:', err)
    res.status(500).json({ error: 'Could not send emails' })
  }
})

// ── START SERVER ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('Gatheritup API running on port ' + PORT)
})
