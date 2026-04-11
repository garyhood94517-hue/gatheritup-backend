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
import cron from 'node-cron'

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

// ── CHANGE PASSWORD ───────────────────────────────────────────────────────────
app.post('/auth/change-password', authRequired, async (req, res) => {
  const { email, currentPassword, newPassword } = req.body
  if (!email || !currentPassword || !newPassword) return res.status(400).json({ error: 'All fields are required.' })
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters.' })
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single()
  if (!user) return res.status(404).json({ error: 'User not found.' })
  if (user.email.toLowerCase() !== email.trim().toLowerCase()) return res.status(400).json({ error: 'Email address does not match our records.' })
  const valid = await bcrypt.compare(currentPassword, user.password_hash)
  if (!valid) return res.status(400).json({ error: 'Current password is incorrect.' })
  const hashedPassword = await bcrypt.hash(newPassword, 12)
  await supabase.from('users').update({ password_hash: hashedPassword }).eq('id', user.id)
  res.json({ success: true })
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
app.get('/api/trustee', authRequired, async (req, res) => {
  const { data } = await supabase.from('users').select('trustee_name, trustee_email, trustee2_name, trustee2_email').eq('id', req.user.id).single()
  res.json({ trustee1_name: data?.trustee_name || '', trustee1_email: data?.trustee_email || '', trustee2_name: data?.trustee2_name || '', trustee2_email: data?.trustee2_email || '' })
})

app.post('/api/trustee', authRequired, async (req, res) => {
  try {
    const { trustee1Name, trustee1Email, trustee2Name, trustee2Email, emailChanged } = req.body
    const { data: existing } = await supabase.from('users').select('first_name, last_name').eq('id', req.user.id).single()
    const fullName = `${existing.first_name} ${existing.last_name}`
    await supabase.from('users').update({
      trustee_name: trustee1Name || null,
      trustee_email: trustee1Email || null,
      trustee2_name: trustee2Name || null,
      trustee2_email: trustee2Email || null
    }).eq('id', req.user.id)
    res.json({ success: true })
    if (emailChanged && trustee1Email && trustee1Name) {
      try {
        await sgMail.send({
          to: trustee1Email,
          from: { name: 'Gatheritup', email: 'support@gatheritup.com' },
          subject: `${fullName} has named you as a Legacy Trustee`,
          text: `Dear ${trustee1Name},\n\n${fullName} has chosen you as their primary Legacy Trustee on Gatheritup — a place where families preserve their most precious memories.\n\nThis means that when the time comes, you are trusted to help preserve and share their family memories with loved ones. You don't need to do anything right now.\n\nWhen the time comes, simply contact us at support@gatheritup.com and we will take care of everything personally.\n\nWith care,\nThe Gatheritup Team`
        })
      } catch(e) { console.error('Trustee 1 email error:', e.message) }
    }
    if (emailChanged && trustee2Email && trustee2Name) {
      try {
        await sgMail.send({
          to: trustee2Email,
          from: { name: 'Gatheritup', email: 'support@gatheritup.com' },
          subject: `${fullName} has named you as a Legacy Trustee`,
          text: `Dear ${trustee2Name},\n\n${fullName} has chosen you as their secondary Legacy Trustee on Gatheritup — a place where families preserve their most precious memories.\n\nThis means that when the time comes, you are trusted to help preserve and share their family memories with loved ones. You don't need to do anything right now.\n\nWhen the time comes, simply contact us at support@gatheritup.com and we will take care of everything personally.\n\nWith care,\nThe Gatheritup Team`
        })
      } catch(e) { console.error('Trustee 2 email error:', e.message) }
    }
  } catch(err) {
    console.error('Trustee save error:', err.message)
    if (!res.headersSent) res.status(500).json({ error: 'Could not save.' })
  }
})


// ── LEGACY ACCESS VIEW PAGE ───────────────────────────────────────────────────
// Read-only page served to trustees after Legacy Access is activated
// Trustees can browse by year (paginated) and export everything with one button

app.get('/legacy/:userId', async (req, res) => {
  try {
    const { userId } = req.params
    const pageSize = 12
    const page = parseInt(req.query.page) || 1
    const filterYear = req.query.year ? parseInt(req.query.year) : null

    const { data: user, error } = await supabase
      .from('users')
      .select('first_name, last_name, legacy_active')
      .eq('id', userId)
      .single()

    if (error || !user) return res.status(404).send('<h2>Page not found.</h2>')
    if (!user.legacy_active) return res.status(403).send(`
      <div style="font-family:'Source Sans 3',Georgia,sans-serif;max-width:500px;margin:80px auto;text-align:center;padding:0 24px;">
        <h2 style="color:#1a1f2e;">Access Not Yet Available</h2>
        <p style="color:#6b7280;line-height:1.7;">Legacy Access for this account has not been activated yet. If you believe this is an error, please contact us at <a href="mailto:support@gatheritup.com" style="color:#0dbbad;">support@gatheritup.com</a>.</p>
      </div>`)

    const { data: allMemories } = await supabase
      .from('memories')
      .select('*')
      .eq('user_id', userId)
      .eq('is_sample', false)
      .order('date', { ascending: false })

    const fullName = `${user.first_name} ${user.last_name}`
    const memoryList = allMemories || []

    const yearsWithMemories = [...new Set(
      memoryList
        .filter(m => m.date)
        .map(m => parseInt(m.date.split('-')[0]))
        .filter(y => !isNaN(y))
    )].sort((a, b) => b - a)

    const activeYear = filterYear && yearsWithMemories.includes(filterYear)
      ? filterYear
      : (yearsWithMemories[0] || null)

    const yearFiltered = activeYear
      ? memoryList.filter(m => m.date && parseInt(m.date.split('-')[0]) === activeYear)
      : memoryList

    const totalCount = yearFiltered.length
    const totalPages = Math.max(1, Math.ceil(totalCount / pageSize))
    const safePage = Math.min(Math.max(1, page), totalPages)
    const pageMemories = yearFiltered.slice((safePage - 1) * pageSize, safePage * pageSize)

    const totalPhotos = memoryList.reduce((n, m) => n + (m.files || []).filter(f => f.type === 'photo').length, 0)
    const totalVideos = memoryList.reduce((n, m) => n + (m.files || []).filter(f => f.type === 'video').length, 0)
    const totalMedia = totalPhotos + totalVideos
    const yearRange = yearsWithMemories.length > 0
      ? (yearsWithMemories[yearsWithMemories.length - 1] + ' \u2013 ' + yearsWithMemories[0])
      : ''

    const months = ['January','February','March','April','May','June','July','August','September','October','November','December']
    const fmtDate = (s) => {
      if (!s) return ''
      const [y, mo, d] = s.split('-')
      if (d && d !== '01') return `${months[parseInt(mo)-1]} ${parseInt(d)}, ${y}`
      if (mo) return `${months[parseInt(mo)-1]} ${y}`
      return y
    }

    const yearPillsHTML = yearsWithMemories.map(y => `
      <a href="/legacy/${userId}?year=${y}&page=1"
         style="display:inline-block;padding:8px 18px;border-radius:20px;font-size:15px;font-family:'Source Sans 3',sans-serif;text-decoration:none;margin:4px;
                ${y === activeYear
                  ? 'background:#0dbbad;color:#fff;border:2px solid #0dbbad;'
                  : 'background:#fff;color:#1a1f2e;border:1.5px solid #d1d5db;'}">${y}</a>
    `).join('')

    const memoriesHTML = pageMemories.length === 0
      ? '<p style="color:#9ca3af;text-align:center;padding:32px 0;">No memories found for this year.</p>'
      : pageMemories.map(m => {
          const files = m.files || []
          const photos = files.filter(f => f.type === 'photo')
          const videos = files.filter(f => f.type === 'video')
          const title = m.title && !m.title.startsWith('IMG_') && !m.title.startsWith('VID_') ? m.title : 'Untitled Memory'
          const firstPhoto = photos[0]
          return `
            <div style="background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;box-shadow:0 1px 3px rgba(0,0,0,.05);">
              ${firstPhoto
                ? `<img src="${firstPhoto.url}" alt="${title}" style="width:100%;height:160px;object-fit:cover;display:block;">`
                : videos[0]
                  ? `<div style="width:100%;height:160px;background:#1a1f2e;display:flex;align-items:center;justify-content:center;"><div style="width:48px;height:48px;border-radius:50%;background:#0dbbad;display:flex;align-items:center;justify-content:center;"><div style="width:0;height:0;border-top:10px solid transparent;border-bottom:10px solid transparent;border-left:18px solid #fff;margin-left:4px;"></div></div></div>`
                  : `<div style="width:100%;height:120px;background:#f0faf8;display:flex;align-items:center;justify-content:center;font-size:36px;">&#128221;</div>`
              }
              <div style="padding:14px 16px;">
                <div style="font-family:'Lora',Georgia,serif;font-size:16px;font-weight:600;color:#1a1f2e;margin-bottom:4px;line-height:1.4;">${title}</div>
                <div style="font-size:13px;color:#9ca3af;margin-bottom:8px;">${fmtDate(m.date)}</div>
                ${m.caption ? `<div style="font-size:14px;color:#374151;line-height:1.6;font-style:italic;margin-bottom:10px;">${m.caption.length > 120 ? m.caption.substring(0, 120) + '\u2026' : m.caption}</div>` : ''}
                ${photos.length > 1 ? `<div style="font-size:12px;color:#9ca3af;margin-top:8px;">${photos.length} photos</div>` : ''}
                ${videos.length > 0 ? `<div style="font-size:12px;color:#9ca3af;margin-top:4px;">${videos.length} ${videos.length === 1 ? 'video' : 'videos'}</div>` : ''}
              </div>
            </div>`
        }).join('')

    const paginationHTML = totalPages <= 1 ? '' : `
      <div style="display:flex;align-items:center;justify-content:center;gap:12px;margin-top:24px;flex-wrap:wrap;">
        ${safePage > 1
          ? `<a href="/legacy/${userId}?year=${activeYear}&page=${safePage - 1}" style="padding:10px 22px;border-radius:8px;background:#fff;color:#1a1f2e;border:1.5px solid #d1d5db;text-decoration:none;font-size:15px;font-family:'Source Sans 3',sans-serif;font-weight:600;">\u2190 Previous</a>`
          : `<span style="padding:10px 22px;border-radius:8px;background:#f3f4f6;color:#d1d5db;border:1.5px solid #e5e7eb;font-size:15px;font-family:'Source Sans 3',sans-serif;">\u2190 Previous</span>`}
        <span style="font-size:15px;color:#6b7280;font-family:'Source Sans 3',sans-serif;">Page ${safePage} of ${totalPages}</span>
        ${safePage < totalPages
          ? `<a href="/legacy/${userId}?year=${activeYear}&page=${safePage + 1}" style="padding:10px 22px;border-radius:8px;background:#fff;color:#1a1f2e;border:1.5px solid #d1d5db;text-decoration:none;font-size:15px;font-family:'Source Sans 3',sans-serif;font-weight:600;">Next \u2192</a>`
          : `<span style="padding:10px 22px;border-radius:8px;background:#f3f4f6;color:#d1d5db;border:1.5px solid #e5e7eb;font-size:15px;font-family:'Source Sans 3',sans-serif;">Next \u2192</span>`}
      </div>`

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>The Memories of ${fullName}</title>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@400;600;700&family=Source+Sans+3:wght@400;500;600&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Source Sans 3',sans-serif;background:#f9fafb;color:#1a1f2e;line-height:1.7;}
.header{background:#0a6b5e;padding:36px 24px;text-align:center;}
.header-line{width:40px;height:1px;background:rgba(255,255,255,0.4);margin:0 auto;}
.header h1{font-family:'Lora',Georgia,serif;color:#fff;font-size:26px;margin:12px 0 8px;line-height:1.3;}
.header p{color:rgba(255,255,255,0.6);font-size:14px;}
.content{max-width:720px;margin:0 auto;padding:24px 16px 80px;}
.notice{background:#f0faf8;border-left:4px solid #0dbbad;border-radius:0 8px 8px 0;padding:16px 18px;margin-bottom:24px;}
.notice p{font-size:15px;color:#085041;line-height:1.7;margin:0;font-family:'Lora',Georgia,serif;font-style:italic;}
.section{background:#fff;border-radius:16px;padding:24px;margin-bottom:24px;border:1px solid #e5e7eb;}
.section-title{font-family:'Lora',Georgia,serif;font-size:20px;color:#1a1f2e;margin-bottom:16px;}
.stats-bar{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:24px;}
.stat{background:#fff;border-radius:12px;border:1px solid #e5e7eb;padding:14px 10px;text-align:center;}
.stat-num{font-size:22px;font-weight:600;color:#1a1f2e;}
.stat-label{font-size:12px;color:#9ca3af;margin-top:2px;}
.export-box{background:#fff;border-radius:16px;border:1px solid #e5e7eb;padding:24px;text-align:center;margin-bottom:24px;}
.export-btn{display:inline-block;background:#0dbbad;color:#fff;font-size:16px;font-weight:600;padding:14px 40px;border-radius:28px;border:none;cursor:pointer;font-family:'Source Sans 3',sans-serif;}
.memory-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
footer{background:#0a6b5e;text-align:center;padding:24px;color:rgba(255,255,255,0.5);font-size:13px;}
footer a{color:rgba(255,255,255,0.8);text-decoration:none;}
@media(max-width:520px){
  .memory-grid{grid-template-columns:1fr;}
  .header h1{font-size:22px;}
  .export-btn{width:100%;padding:16px 24px;}
  .content{padding:16px 12px 80px;}
}
</style>
</head>
<body>

<div class="header">
  <div class="header-line"></div>
  <h1>The Memories of ${fullName}</h1>
  <p>${yearRange ? yearRange + ' &middot; ' : ''}${memoryList.length} memories preserved</p>
  <div class="header-line" style="margin-top:12px;"></div>
</div>

<div class="content">

  <div class="notice">
    <p>These memories have been entrusted to you. Take your time &mdash; there is no rush.</p>
  </div>

  <div class="stats-bar">
    <div class="stat"><div class="stat-num">${memoryList.length}</div><div class="stat-label">memories</div></div>
    <div class="stat"><div class="stat-num">${yearsWithMemories.length}</div><div class="stat-label">${yearsWithMemories.length === 1 ? 'year' : 'years'}</div></div>
    <div class="stat"><div class="stat-num">${totalMedia}</div><div class="stat-label">photos &amp; videos</div></div>
  </div>

  <div class="export-box">
    <p style="font-size:15px;color:#6b7280;margin-bottom:16px;line-height:1.6;">When you are ready, save these memories somewhere safe for the family.</p>
    <button class="export-btn" id="exportBtn" onclick="exportAll()">Export all memories</button>
    <div style="font-size:13px;color:#9ca3af;margin-top:10px;">Download links will be sent to your email &mdash; organized by year</div>
  </div>

  <!-- Export confirmation popup -->
  <div id="exportPopup" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.4);z-index:1000;align-items:center;justify-content:center;">
    <div style="background:#fff;border-radius:16px;padding:32px 24px;max-width:340px;width:90%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,0.15);">
      <div style="font-size:40px;margin-bottom:12px;">&#10003;</div>
      <div style="font-size:17px;font-weight:700;color:#085041;margin-bottom:8px;">Your download links are on their way!</div>
      <div style="font-size:14px;color:#6b7280;margin-bottom:24px;line-height:1.6;">Check your email &mdash; links are organized by year for easy saving.</div>
      <button onclick="closePopup()" style="background:#0dbbad;color:#fff;border:none;border-radius:10px;padding:12px 32px;font-size:15px;font-weight:700;cursor:pointer;">OK</button>
    </div>
  </div>

  ${yearsWithMemories.length > 0 ? `
  <div class="section">
    <div class="section-title">Browse memories${activeYear ? ' &mdash; ' + activeYear : ''}</div>
    <div style="margin-bottom:16px;line-height:1;">${yearPillsHTML}</div>
    <div style="font-size:13px;color:#9ca3af;margin-bottom:16px;">Showing ${(safePage - 1) * pageSize + 1}&ndash;${Math.min(safePage * pageSize, totalCount)} of ${totalCount} ${activeYear ? activeYear + ' ' : ''}memories</div>
    <div class="memory-grid">${memoriesHTML}</div>
    ${paginationHTML}
  </div>` : '<p style="color:#9ca3af;text-align:center;padding:32px 0;">No memories found.</p>'}

</div>

<footer>
  <p>&copy; 2026 Gatheritup.com &middot; <a href="mailto:support@gatheritup.com">support@gatheritup.com</a></p>
  <p style="margin-top:6px;">If you need any help, please reach out &mdash; we are here for you.</p>
</footer>

<script>
function closePopup() {
  document.getElementById('exportPopup').style.display = 'none'
}

async function exportAll() {
  const btn = document.getElementById('exportBtn')
  btn.textContent = 'Sending\u2026'
  btn.disabled = true
  try {
    const res = await fetch('/api/legacy-export', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ userId: '${userId}' })
    })
    const data = await res.json()
    if (data.success) {
      btn.textContent = 'Export all memories'
      btn.disabled = false
      const popup = document.getElementById('exportPopup')
      popup.style.display = 'flex'
      setTimeout(() => { popup.style.display = 'none' }, 5000)
    } else {
      alert('Something went wrong. Please try again or contact support@gatheritup.com')
      btn.textContent = 'Export all memories'
      btn.disabled = false
    }
  } catch(e) {
    alert('Something went wrong. Please try again or contact support@gatheritup.com')
    btn.textContent = 'Export all memories'
    btn.disabled = false
  }
}
</script>
</body>
</html>`)
  } catch(err) {
    console.error('Legacy view error:', err.message)
    res.status(500).send('<h2>Something went wrong. Please contact support@gatheritup.com</h2>')
  }
})

// ── LEGACY EXPORT EMAIL ───────────────────────────────────────────────────────
// Sends ALL memories to trustee email organized by year

app.post('/api/legacy-export', async (req, res) => {
  try {
    const { userId } = req.body
    if (!userId) return res.status(400).json({ error: 'Missing userId.' })

    const { data: user } = await supabase.from('users')
      .select('first_name, last_name, trustee_email, trustee_name, trustee2_email, trustee2_name, legacy_active')
      .eq('id', userId).single()

    if (!user || !user.legacy_active) return res.status(403).json({ error: 'Legacy access not active.' })

    const fullName = `${user.first_name} ${user.last_name}`
    const months = ['January','February','March','April','May','June','July','August','September','October','November','December']
    const fmtDate = (s) => {
      if (!s) return ''
      const [y, mo, d] = s.split('-')
      if (d && d !== '01') return `${months[parseInt(mo)-1]} ${parseInt(d)}, ${y}`
      if (mo) return `${months[parseInt(mo)-1]} ${y}`
      return y
    }

    const { data: memories } = await supabase.from('memories')
      .select('*')
      .eq('user_id', userId)
      .eq('is_sample', false)
      .order('date', { ascending: false })

    const memoryList = memories || []
    if (memoryList.length === 0) return res.status(400).json({ error: 'No memories found.' })

    const byYear = {}
    memoryList.forEach(m => {
      const y = m.date ? m.date.split('-')[0] : 'Unknown'
      if (!byYear[y]) byYear[y] = []
      byYear[y].push(m)
    })

    let emailBody = `<div style="font-family:Georgia,serif;max-width:600px;margin:0 auto;color:#1a1f2e;">`
    emailBody += `<div style="background:#0a6b5e;padding:28px 32px;border-radius:12px 12px 0 0;text-align:center;">`
    emailBody += `<div style="width:40px;height:1px;background:rgba(255,255,255,0.4);margin:0 auto 14px;"></div>`
    emailBody += `<h1 style="font-family:Georgia,serif;color:#fff;margin:0;font-size:22px;font-weight:600;">The Memories of ${fullName}</h1>`
    emailBody += `<p style="color:rgba(255,255,255,0.6);margin:8px 0 0;font-size:14px;">${memoryList.length} memories &mdash; all years</p>`
    emailBody += `<div style="width:40px;height:1px;background:rgba(255,255,255,0.4);margin:14px auto 0;"></div>`
    emailBody += `</div>`
    emailBody += `<div style="background:#f9fafb;padding:28px 32px;">`
    emailBody += `<div style="background:#f0faf8;border-left:4px solid #0dbbad;border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:24px;">`
    emailBody += `<p style="font-size:15px;color:#085041;font-style:italic;font-family:Georgia,serif;margin:0 0 10px;line-height:1.7;">Your loved one&apos;s memories, photos, and videos are ready to download.</p>`
    emailBody += `<p style="font-size:15px;color:#085041;font-style:italic;font-family:Georgia,serif;margin:0;line-height:1.7;">Please save these memories somewhere safe soon &mdash; we want to make sure nothing is ever lost.</p>`
    emailBody += `</div>`

    Object.keys(byYear).sort((a,b) => b - a).forEach(year => {
      emailBody += `<div style="font-size:13px;font-weight:700;color:#9ca3af;letter-spacing:.08em;text-transform:uppercase;margin:24px 0 12px;border-bottom:1px solid #e5e7eb;padding-bottom:6px;">${year}</div>`
      byYear[year].forEach(m => {
        const files = m.files || []
        const photos = files.filter(f => f.type === 'photo')
        const videos = files.filter(f => f.type === 'video')
        const title = m.title && !m.title.startsWith('IMG_') && !m.title.startsWith('VID_') ? m.title : 'Untitled Memory'
        emailBody += `<div style="background:#fff;border-radius:10px;padding:16px 20px;margin-bottom:12px;border:1px solid #e5e7eb;">`
        emailBody += `<h2 style="font-size:16px;color:#1a1f2e;margin:0 0 4px;font-family:Georgia,serif;">${title}</h2>`
        emailBody += `<p style="font-size:13px;color:#9ca3af;margin:0 0 10px;">${fmtDate(m.date)}</p>`
        photos.forEach((f,i) => { emailBody += `<a href="${f.url}" style="display:block;background:#f0faf8;color:#0dbbad;border:1px solid #0dbbad;border-radius:6px;padding:8px 14px;font-size:13px;text-decoration:none;margin-bottom:6px;font-weight:600;">&#128247; Photo ${i+1} &mdash; Download</a>` })
        videos.forEach((f,i) => { emailBody += `<a href="${f.url}" style="display:block;background:#f0faf8;color:#0dbbad;border:1px solid #0dbbad;border-radius:6px;padding:8px 14px;font-size:13px;text-decoration:none;margin-bottom:6px;font-weight:600;">&#127916; Video ${i+1} &mdash; Download</a>` })
        emailBody += `</div>`
      })
    })

    emailBody += `<div style="border-top:1px solid #e5e7eb;margin-top:24px;padding-top:20px;">`
    emailBody += `<p style="font-size:14px;color:#6b7280;line-height:1.7;margin:0 0 16px;">We recommend saving everything to Google Drive, iCloud, or an external hard drive for safekeeping.</p>`
    emailBody += `<p style="font-size:13px;color:#9ca3af;margin:0;">With care &mdash; The Gatheritup Team &middot; <a href="mailto:support@gatheritup.com" style="color:#0dbbad;">support@gatheritup.com</a></p>`
    emailBody += `</div>`
    emailBody += `</div>`
    emailBody += `<div style="background:#0a6b5e;padding:16px 32px;border-radius:0 0 12px 12px;text-align:center;">`
    emailBody += `<p style="color:rgba(255,255,255,0.5);font-size:13px;margin:0;">&copy; 2026 Gatheritup.com</p>`
    emailBody += `</div></div>`

    const recipients = []
    if (user.trustee_email) recipients.push({ email: user.trustee_email, name: user.trustee_name || 'Trustee' })
    if (user.trustee2_email) recipients.push({ email: user.trustee2_email, name: user.trustee2_name || 'Trustee' })
    if (recipients.length === 0) return res.status(400).json({ error: 'No trustee email on file.' })

    for (const r of recipients) {
      await sgMail.send({
        to: r.email,
        from: { name: 'Gatheritup', email: 'support@gatheritup.com' },
        subject: `The Memories of ${fullName} \u2014 Ready to Download`,
        html: emailBody
      })
    }

    res.json({ success: true })
  } catch(err) {
    console.error('Legacy export error:', err.message)
    res.status(500).json({ error: 'Export failed.' })
  }
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
  const marketingText = 'Enjoyed this memory? Gatheritup helps families preserve their photos, videos, and the stories behind them — all in one beautiful place.'
  const marketingCta  = 'Try it free for 30 days — no credit card needed.'

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
      <p>${marketingText}</p>
      <p><strong>${marketingCta}</strong></p>
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
    .select('id, first_name, last_name, email, phone, status, trial_end, paid_at, created_at, comm_pref, trustee_name, trustee_email, trustee_activation, trustee2_name, trustee2_email, legacy_active')
    .order('created_at', { ascending: false })
  if (error) return res.status(500).json({ error: 'Could not fetch users' })
  res.json(users)
})

app.patch('/api/admin/users/:id/trustee', adminAuth, async (req, res) => {
  const { id } = req.params
  const { trusteeName, trusteeEmail, trustee2Name, trustee2Email, activationMode } = req.body
  const { error } = await supabase.from('users').update({
    trustee_name: trusteeName,
    trustee_email: trusteeEmail,
    trustee2_name: trustee2Name || null,
    trustee2_email: trustee2Email || null,
    trustee_activation: activationMode
  }).eq('id', id)
  if (error) return res.status(500).json({ error: 'Could not update trustee' })
  res.json({ success: true })
})

// ── LEGACY ACCESS ACTIVATION ──────────────────────────────────────────────────
app.patch('/api/admin/users/:id/legacy-activate', adminAuth, async (req, res) => {
  try {
    const { id } = req.params
    const { data: user, error } = await supabase.from('users')
      .select('first_name, last_name, trustee_name, trustee_email, trustee2_name, trustee2_email, legacy_active')
      .eq('id', id).single()
    if (error) return res.status(500).json({ error: 'User not found' })
    const newState = !user.legacy_active
    await supabase.from('users').update({ legacy_active: newState }).eq('id', id)
    if (newState) {
      const fullName = `${user.first_name} ${user.last_name}`
      const legacyLink = `https://gatheritup-backend-production.up.railway.app/legacy/${id}`

      const buildEmail = (toName) => `
<div style="font-family:Georgia,serif;max-width:600px;margin:0 auto;color:#1a1f2e;">
  <div style="background:#1a1f2e;padding:24px 32px;border-radius:12px 12px 0 0;">
    <h1 style="color:#fff;margin:0;font-size:22px;font-weight:600;">The Memories of ${fullName}</h1>
    <p style="color:rgba(255,255,255,0.6);margin:6px 0 0;font-size:14px;">A private Legacy Access message</p>
  </div>
  <div style="background:#f9fafb;padding:28px 32px;">
    <p style="font-size:16px;color:#1a1f2e;margin:0 0 12px;">Dear ${toName},</p>
    <p style="font-size:15px;color:#374151;line-height:1.7;margin:0 0 12px;">We are reaching out on behalf of ${fullName}'s family.</p>
    <p style="font-size:15px;color:#374151;line-height:1.7;margin:0 0 24px;">You have been granted Legacy Access to ${fullName}'s Gatheritup memories. Please take your time browsing their preserved photos, videos, and stories — and when you are ready, you can download everything to save for the family.</p>
    <div style="text-align:center;margin:0 0 24px;">
      <a href="${legacyLink}" style="display:inline-block;background:#0dbbad;color:#fff;font-size:16px;font-weight:600;padding:14px 36px;border-radius:28px;text-decoration:none;font-family:'Helvetica Neue',Arial,sans-serif;">View ${fullName}'s memories</a>
    </div>
    <div style="background:#f0faf8;border-left:4px solid #0dbbad;border-radius:0 8px 8px 0;padding:14px 18px;margin:0 0 24px;">
      <p style="font-size:14px;color:#085041;margin:0;line-height:1.6;">This link is private and intended only for you. Please treat it with care.</p>
    </div>
    <p style="font-size:14px;color:#6b7280;margin:0;line-height:1.6;">If you need any help at any time, please reach us at <a href="mailto:support@gatheritup.com" style="color:#0dbbad;">support@gatheritup.com</a> — we are here for you.</p>
  </div>
  <div style="background:#1a1f2e;padding:16px 32px;border-radius:0 0 12px 12px;text-align:center;">
    <p style="color:rgba(255,255,255,0.5);font-size:13px;margin:0;">With care &mdash; The Gatheritup Team</p>
  </div>
</div>`

      if (user.trustee_email && user.trustee_name) {
        try {
          await sgMail.send({
            to: user.trustee_email,
            from: { name: 'Gatheritup', email: 'support@gatheritup.com' },
            subject: `The Memories of ${fullName} — Legacy Access`,
            html: buildEmail(user.trustee_name)
          })
        } catch(e) { console.error('Legacy email 1 error:', e.message) }
      }
      if (user.trustee2_email && user.trustee2_name) {
        try {
          await sgMail.send({
            to: user.trustee2_email,
            from: { name: 'Gatheritup', email: 'support@gatheritup.com' },
            subject: `The Memories of ${fullName} — Legacy Access`,
            html: buildEmail(user.trustee2_name)
          })
        } catch(e) { console.error('Legacy email 2 error:', e.message) }
      }
    }
    res.json({ success: true, legacy_active: newState })
  } catch(err) {
    console.error('Legacy activate error:', err.message)
    res.status(500).json({ error: 'Could not update legacy access' })
  }
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

// ── ADMIN SETTINGS ────────────────────────────────────────────────────────────
app.get('/api/admin/settings', adminAuth, async (req, res) => {
  const { data } = await supabase.from('settings').select('key, value')
  const settings = {}
  if (data) data.forEach(row => { settings[row.key] = row.value })
  res.json(settings)
})

app.post('/api/admin/settings', adminAuth, async (req, res) => {
  const { key, value } = req.body
  if (!key) return res.status(400).json({ error: 'Key is required.' })
  await supabase.from('settings').upsert({ key, value }, { onConflict: 'key' })
  res.json({ success: true })
})

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email is required.' })
  const { data: user } = await supabase.from('users').select('id, first_name, email').eq('email', email.toLowerCase()).single()
  if (!user) return res.json({ success: true })
  const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  const resetExpiry = new Date(Date.now() + 60 * 60 * 1000)
  await supabase.from('users').update({ reset_token: resetToken, reset_expiry: resetExpiry.toISOString() }).eq('id', user.id)
  const resetUrl = 'https://gatheritup.com/reset-password.html?token=' + resetToken
  try {
    await sgMail.send({
      to: user.email,
      from: 'support@gatheritup.com',
      subject: 'Reset Your Gatheritup Password',
      html: `<p>Hi ${user.first_name},</p><p>We received a request to reset your Gatheritup password. Click below to set a new password. This link expires in 1 hour.</p><p><a href="${resetUrl}" style="background:#0dbbad;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;">Reset My Password</a></p><p>If you did not request this, you can safely ignore this email.</p><p>— The Gatheritup Team</p>`
    })
  } catch (err) {
    console.error('Forgot password email error:', err)
  }
  res.json({ success: true })
})

// ── RESET PASSWORD ────────────────────────────────────────────────────────────
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body
  if (!token || !password) return res.status(400).json({ error: 'Token and password are required.' })
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' })
  const { data: user } = await supabase.from('users').select('id, reset_token, reset_expiry').eq('reset_token', token).single()
  if (!user) return res.status(400).json({ error: 'Invalid or expired reset link.' })
  if (new Date() > new Date(user.reset_expiry)) return res.status(400).json({ error: 'This reset link has expired. Please request a new one.' })
  const hashedPassword = await bcrypt.hash(password, 12)
  await supabase.from('users').update({ password_hash: hashedPassword, reset_token: null, reset_expiry: null }).eq('id', user.id)
  res.json({ success: true })
})

// ── EMAIL SCHEDULER ───────────────────────────────────────────────────────────
const EMAIL_DAYS = [1, 7, 14, 20, 27, 30]

async function runEmailScheduler() {
  console.log('📧 Running email scheduler:', new Date().toISOString())
  try {
    const { data: settingsRows } = await supabase.from('settings').select('key, value')
    const settings = {}
    if (settingsRows) settingsRows.forEach(r => { settings[r.key] = r.value })

    const defaults = {
      1:  { subject: 'Welcome to Gatheritup, {first_name}! 🎉',          body: 'Hi {first_name},\n\nWelcome to Gatheritup! To get started, tap the + button to add your first memory.\n\nIf you need any help, just reply to this email.\n\n— Gary & The Gatheritup Team' },
      7:  { subject: 'Did you know you can share memories with family?',  body: 'Hi {first_name},\n\nYou\'ve been with us for a week! Did you know you can share any memory with family? Just open a memory and tap Share.\n\n— Gary & The Gatheritup Team' },
      14: { subject: 'A tip to keep your memories organized',             body: 'Hi {first_name},\n\nTip: Use Categories to organize your memories. Create categories like "Family Vacations" or "Holidays" and filter by them anytime.\n\n— Gary & The Gatheritup Team' },
      20: { subject: 'Your Gatheritup trial ends in 10 days',            body: 'Hi {first_name},\n\nYour free trial ends in 10 days. Upgrade for just $49.95 — one-time, no subscription ever.\n\nUpgrade here: https://gatheritup.com\n\n— Gary & The Gatheritup Team' },
      27: { subject: 'Your Gatheritup trial ends in 3 days ⏰',           body: 'Hi {first_name},\n\nJust 3 days left on your trial! Don\'t lose your memories.\n\nUpgrade for $49.95 here: https://gatheritup.com\n\n— Gary & The Gatheritup Team' },
      30: { subject: 'Your Gatheritup trial has ended',                  body: 'Hi {first_name},\n\nYour 30-day trial has ended. Your memories are safely stored and waiting for you.\n\nUpgrade for $49.95 to regain full access: https://gatheritup.com\n\n— Gary & The Gatheritup Team' },
    }

    const { data: users } = await supabase.from('users').select('id, first_name, email, created_at, status, comm_pref').eq('status', 'trial').eq('comm_pref', 'email')
    if (!users || !users.length) return console.log('No trial users found.')

    const today = new Date()
    today.setHours(0, 0, 0, 0)

    for (const user of users) {
      const signupDate = new Date(user.created_at)
      signupDate.setHours(0, 0, 0, 0)
      const daysSinceSignup = Math.round((today - signupDate) / (1000 * 60 * 60 * 24))

      if (!EMAIL_DAYS.includes(daysSinceSignup)) continue

      const subjectTemplate = settings[`email_subject_${daysSinceSignup}`] || defaults[daysSinceSignup]?.subject
      const bodyTemplate    = settings[`email_body_${daysSinceSignup}`]    || defaults[daysSinceSignup]?.body
      if (!subjectTemplate || !bodyTemplate) continue

      const subject = subjectTemplate.replace(/{first_name}/g, user.first_name)
      const body    = bodyTemplate.replace(/{first_name}/g, user.first_name)
      const html    = body.replace(/\n/g, '<br>')

      try {
        await sgMail.send({
          to:      user.email,
          from:    'support@gatheritup.com',
          subject,
          html:    `<div style="font-family:sans-serif;font-size:16px;line-height:1.7;color:#1a1f2e;max-width:560px;margin:0 auto;padding:24px;">${html}</div>`
        })
        console.log(`✅ Day ${daysSinceSignup} email sent to ${user.email}`)
      } catch (err) {
        console.error(`❌ Failed to send to ${user.email}:`, err.message)
      }
    }
  } catch (err) {
    console.error('Scheduler error:', err)
  }
}

cron.schedule('0 9 * * *', runEmailScheduler)
console.log('📅 Email scheduler started — runs daily at 9:00 AM UTC')

// ── FILE UPLOAD ───────────────────────────────────────────────────────────────
app.post('/api/upload', authRequired, upload.single('file'), async (req, res) => {
  try {
    console.log('[UPLOAD] Request received from user:', req.user?.id)
    if (!req.file) {
      console.log('[UPLOAD] No file in request')
      return res.status(400).json({ error: 'No file provided.' })
    }
    console.log('[UPLOAD] File received:', req.file.originalname, req.file.mimetype, req.file.size, 'bytes')
    const ext = (req.file.originalname || 'file.jpg').split('.').pop() || 'jpg'
    const path = `${req.user.id}/${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`
    console.log('[UPLOAD] Uploading to Supabase path:', path)
    const { data: uploadData, error } = await supabase.storage
      .from('memories')
      .upload(path, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: true
      })
    if (error) {
      console.error('[UPLOAD] Supabase Storage error:', JSON.stringify(error))
      throw error
    }
    console.log('[UPLOAD] Supabase upload success:', JSON.stringify(uploadData))
    const { data: { publicUrl } } = supabase.storage
      .from('memories')
      .getPublicUrl(path)
    console.log('[UPLOAD] Public URL:', publicUrl)
    res.json({ url: publicUrl, path })
  } catch (err) {
    console.error('[UPLOAD] Error:', err.message, err.stack)
    res.status(500).json({ error: 'Upload failed: ' + err.message })
  }
})


// ── MEMORY EXPORT ─────────────────────────────────────────────────────────────
// Sends an email with all stories and Supabase photo/video links for a quarter

app.post('/api/export', authRequired, async (req, res) => {
  try {
    const { year, quarter } = req.body
    if (!year || !quarter) return res.status(400).json({ error: 'Year and quarter required.' })

    // Get user info
    const { data: user } = await supabase.from('users').select('first_name, last_name, email').eq('id', req.user.id).single()
    const fullName = `${user.first_name} ${user.last_name}`

    // Get all memories for this user
    const { data: memories } = await supabase.from('memories').select('*').eq('user_id', req.user.id).eq('is_sample', false)

    // Filter by quarter
    const quarterStart = new Date(`${year}-${String((quarter - 1) * 3 + 1).padStart(2, '0')}-01`)
    const quarterEnd = new Date(`${year}-${String(quarter * 3).padStart(2, '0')}-31`)
    const quarterNames = { 1: 'January — March', 2: 'April — June', 3: 'July — September', 4: 'October — December' }

    const filtered = (memories || []).filter(m => {
      if (!m.date) return false
      const d = new Date(m.date)
      return d >= quarterStart && d <= quarterEnd
    }).sort((a, b) => new Date(a.date) - new Date(b.date))

    if (filtered.length === 0) return res.status(400).json({ error: 'No memories found for this quarter.' })

    // Build email body
    let emailBody = `<div style="font-family:Georgia,serif;max-width:600px;margin:0 auto;color:#1a1f2e;">`
    emailBody += `<div style="background:#0dbbad;padding:24px 32px;border-radius:12px 12px 0 0;">`
    emailBody += `<h1 style="color:#fff;margin:0;font-size:24px;">Your Gatheritup Memories</h1>`
    emailBody += `<p style="color:#e0f7f5;margin:8px 0 0;font-size:16px;">Q${quarter} ${year} — ${quarterNames[quarter]}</p>`
    emailBody += `</div>`
    emailBody += `<div style="background:#f9fafb;padding:24px 32px;">`
    emailBody += `<p style="color:#6b7280;font-size:15px;margin:0 0 24px;">Dear ${user.first_name}, here are your memories from ${quarterNames[quarter]} ${year}. Click any download link to save your photos and videos.</p>`

    const fmtDate = (s) => {
      if (!s) return ''
      const months = ['January','February','March','April','May','June','July','August','September','October','November','December']
      const [y, mo, d] = s.split('-')
      if (d && d !== '01') return `${months[parseInt(mo,10)-1]} ${parseInt(d,10)}, ${y}`
      if (mo) return `${months[parseInt(mo,10)-1]} ${y}`
      return y
    }

    filtered.forEach((m, idx) => {
      const files = m.files || []
      const photos = files.filter(f => f.type === 'photo')
      const videos = files.filter(f => f.type === 'video')
      const title = m.title && !m.title.startsWith('IMG_') && !m.title.startsWith('VID_') ? m.title : 'Untitled Memory'

      emailBody += `<div style="background:#fff;border-radius:10px;padding:20px 24px;margin-bottom:20px;border:1px solid #e5e7eb;">`
      emailBody += `<h2 style="font-size:18px;color:#1a1f2e;margin:0 0 4px;">${idx + 1}. ${title}</h2>`
      emailBody += `<p style="font-size:13px;color:#9ca3af;margin:0 0 12px;">${fmtDate(m.date)}</p>`

      if (m.caption) {
        emailBody += `<p style="font-size:15px;color:#374151;line-height:1.7;margin:0 0 16px;font-style:italic;">${m.caption}</p>`
      }

      // Per-file captions
      files.forEach(f => {
        if (f.caption) {
          emailBody += `<p style="font-size:14px;color:#6b7280;margin:0 0 8px;">📝 ${f.caption}</p>`
        }
      })

      // Download links
      if (photos.length > 0) {
        emailBody += `<div style="margin-top:12px;">`
        emailBody += `<p style="font-size:13px;font-weight:700;color:#0dbbad;margin:0 0 8px;">📷 Photos (${photos.length})</p>`
        photos.forEach((f, i) => {
          emailBody += `<a href="${f.url}" style="display:inline-block;background:#f0faf8;color:#0dbbad;border:1px solid #0dbbad;border-radius:6px;padding:6px 14px;font-size:13px;text-decoration:none;margin:0 6px 6px 0;">Download Photo ${i + 1}</a>`
        })
        emailBody += `</div>`
      }

      if (videos.length > 0) {
        emailBody += `<div style="margin-top:8px;">`
        emailBody += `<p style="font-size:13px;font-weight:700;color:#0dbbad;margin:0 0 8px;">🎬 Videos (${videos.length})</p>`
        videos.forEach((f, i) => {
          emailBody += `<a href="${f.url}" style="display:inline-block;background:#f0faf8;color:#0dbbad;border:1px solid #0dbbad;border-radius:6px;padding:6px 14px;font-size:13px;text-decoration:none;margin:0 6px 6px 0;">Download Video ${i + 1}</a>`
        })
        emailBody += `</div>`
      }

      emailBody += `</div>`
    })

    // Suggestions
    emailBody += `<div style="background:#f0faf8;border-left:4px solid #0dbbad;border-radius:8px;padding:16px 20px;margin-top:8px;">`
    emailBody += `<p style="font-size:15px;color:#085041;font-weight:700;margin:0 0 10px;">Once you receive this email, download your memories, photos and videos right away and save them somewhere safe.</p>`
    emailBody += `<p style="font-size:14px;color:#085041;font-weight:700;margin:0 0 8px;">Where to save your photos and videos:</p>`
    emailBody += `<p style="font-size:14px;color:#085041;margin:0 0 6px;">📱 iPhone or iPad — Save to your Photos app or iCloud Drive</p>`
    emailBody += `<p style="font-size:14px;color:#085041;margin:0 0 6px;">💻 Windows or Mac — Save to your Documents folder or an external drive</p>`
    emailBody += `<p style="font-size:14px;color:#085041;margin:0;">☁️ Cloud — Save to Google Drive or Dropbox for access anywhere</p>`
    emailBody += `</div>`

    emailBody += `<p style="font-size:13px;color:#9ca3af;text-align:center;margin-top:24px;">Your memories are safely stored in Gatheritup's secure cloud. Export anytime from the app menu.</p>`
    emailBody += `</div>`
    emailBody += `<div style="background:#1a1f2e;padding:16px 32px;border-radius:0 0 12px 12px;text-align:center;">`
    emailBody += `<p style="color:rgba(255,255,255,0.6);font-size:13px;margin:0;">© 2026 Gatheritup.com · <a href="mailto:support@gatheritup.com" style="color:#0dbbad;">support@gatheritup.com</a></p>`
    emailBody += `</div></div>`

    await sgMail.send({
      to: user.email,
      from: { name: 'Gatheritup', email: 'support@gatheritup.com' },
      subject: `Your Gatheritup Memories — Q${quarter} ${year}`,
      html: emailBody
    })

    res.json({ success: true, count: filtered.length })
  } catch (err) {
    console.error('Export error:', err.message)
    res.status(500).json({ error: 'Could not send export email. Please try again.' })
  }
})

// ── MEMORIES API ──────────────────────────────────────────────────────────────

// GET all memories for current user
app.get('/api/memories', authRequired, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('memories')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
    if (error) throw error
    res.json(data || [])
  } catch (err) {
    console.error('GET memories error:', err)
    res.status(500).json({ error: 'Could not load memories.' })
  }
})

// POST save a new memory
app.post('/api/memories', authRequired, async (req, res) => {
  try {
    const { memory_id, title, date, caption, groups, files, is_sample } = req.body
    const { data, error } = await supabase
      .from('memories')
      .upsert({
        user_id: req.user.id,
        memory_id,
        title,
        date,
        caption,
        groups: groups || [],
        files: files || [],
        is_sample: is_sample || false,
        updated_at: new Date().toISOString()
      }, { onConflict: 'user_id,memory_id' })
      .select()
      .single()
    if (error) throw error
    res.json(data)
  } catch (err) {
    console.error('POST memory error:', err)
    res.status(500).json({ error: 'Could not save memory.' })
  }
})

// PUT update an existing memory
app.put('/api/memories/:memory_id', authRequired, async (req, res) => {
  try {
    const { title, date, caption, groups, files } = req.body
    const { data, error } = await supabase
      .from('memories')
      .update({ title, date, caption, groups: groups || [], files: files || [], updated_at: new Date().toISOString() })
      .eq('user_id', req.user.id)
      .eq('memory_id', req.params.memory_id)
      .select()
      .single()
    if (error) throw error
    res.json(data)
  } catch (err) {
    console.error('PUT memory error:', err)
    res.status(500).json({ error: 'Could not update memory.' })
  }
})

// DELETE a memory
app.delete('/api/memories/:memory_id', authRequired, async (req, res) => {
  try {
    const { error } = await supabase
      .from('memories')
      .delete()
      .eq('user_id', req.user.id)
      .eq('memory_id', req.params.memory_id)
    if (error) throw error
    res.json({ success: true })
  } catch (err) {
    console.error('DELETE memory error:', err)
    res.status(500).json({ error: 'Could not delete memory.' })
  }
})

// ── START SERVER ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('Gatheritup API running on port ' + PORT)
})
