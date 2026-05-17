<script setup>
import { computed, onMounted, reactive, ref } from 'vue'

const navOpen = ref(false)
const year = new Date().getFullYear()

const services = [
  {
    icon: '🌿',
    title: 'Individual therapy',
    body: 'One-on-one sessions for anxiety, burnout, grief, and life transitions — at your pace, on your schedule.'
  },
  {
    icon: '🤝',
    title: 'Couples & relationships',
    body: 'Structured sessions with relationship-trained therapists. Reconnect, repair, and build something stronger.'
  },
  {
    icon: '🧭',
    title: 'Career & purpose',
    body: 'Coaching-informed therapy for high-pressure careers, leadership transitions, and finding direction.'
  },
  {
    icon: '🌅',
    title: 'Wellness check-ins',
    body: 'Short, focused 30-minute sessions for ongoing maintenance — keep what is working, working.'
  }
]

const therapists = [
  {
    initials: 'AR',
    name: 'Dr. Amara Reyes',
    credentials: 'PhD, Licensed Clinical Psychologist',
    focus: 'Anxiety · Trauma · Mindfulness',
    bio: '12 years guiding clients through anxiety and trauma recovery using ACT and EMDR.'
  },
  {
    initials: 'MC',
    name: 'Marcus Chen, LMFT',
    credentials: 'Licensed Marriage & Family Therapist',
    focus: 'Couples · Family systems',
    bio: 'Gottman-trained. Specializes in communication repair and rebuilding trust.'
  },
  {
    initials: 'SO',
    name: 'Sofía Okafor, LCSW',
    credentials: 'Licensed Clinical Social Worker',
    focus: 'Burnout · Identity · Career',
    bio: 'Works with executives and creatives navigating high-stakes change and burnout recovery.'
  }
]

const focusOptions = [
  'Anxiety or stress',
  'Depression or low mood',
  'Relationship support',
  'Burnout / career',
  'Grief or loss',
  'Identity & life transitions',
  'Something else'
]

const timeSlots = [
  '08:00', '09:00', '10:00', '11:00',
  '13:00', '14:00', '15:00', '16:00', '17:00', '18:00'
]

const form = reactive({
  name: '',
  email: '',
  date: '',
  time: '',
  focus: '',
  notes: ''
})

const errors = reactive({})
const submitting = ref(false)
const submitted = ref(null) // last successful booking
const bookingsCount = ref(0)

const today = computed(() => {
  const d = new Date()
  const y = d.getFullYear()
  const m = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return `${y}-${m}-${day}`
})

const STORAGE_KEY = 'waystar.bookings.v1'

onMounted(() => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) bookingsCount.value = JSON.parse(raw).length
  } catch (_) { /* localStorage unavailable */ }
})

function validate() {
  const next = {}
  if (!form.name.trim()) next.name = 'Please tell us your name.'
  if (!form.email.trim()) {
    next.email = 'Email is required.'
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) {
    next.email = 'Please enter a valid email address.'
  }
  if (!form.date) {
    next.date = 'Pick a preferred date.'
  } else if (form.date < today.value) {
    next.date = 'Please pick today or a future date.'
  }
  if (!form.time) next.time = 'Choose a time slot.'
  if (!form.focus) next.focus = 'Let us know what you would like to focus on.'

  Object.keys(errors).forEach((k) => delete errors[k])
  Object.assign(errors, next)
  return Object.keys(next).length === 0
}

function persistBooking(booking) {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    const list = raw ? JSON.parse(raw) : []
    list.push(booking)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list))
    bookingsCount.value = list.length
  } catch (_) { /* ignore — non-persistent mode */ }
}

const submitError = ref('')
const BOOKING_ENDPOINT = '/cgi-bin/book.py'

async function postBooking(payload) {
  const res = await fetch(BOOKING_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify(payload)
  })
  let data = null
  try { data = await res.json() } catch (_) { /* non-JSON */ }
  return { res, data }
}

async function submit() {
  submitError.value = ''
  if (!validate()) {
    const first = document.querySelector('[aria-invalid="true"]')
    if (first) first.focus()
    return
  }
  submitting.value = true
  const payload = {
    name: form.name.trim(),
    email: form.email.trim(),
    date: form.date,
    time: form.time,
    focus: form.focus,
    notes: form.notes.trim()
  }

  let serverId = null
  let serverRef = null
  let serverCreatedAt = null
  let serverReachable = true
  try {
    const { res, data } = await postBooking(payload)
    if (res.status === 201 && data && data.ok) {
      serverId = data.id
      serverRef = data.reference
      serverCreatedAt = data.created_at
    } else if (res.status === 422 && data && data.errors) {
      Object.keys(errors).forEach((k) => delete errors[k])
      Object.assign(errors, data.errors)
      submitting.value = false
      const first = document.querySelector('[aria-invalid="true"]')
      if (first) first.focus()
      return
    } else {
      throw new Error(`booking_failed_${res.status}`)
    }
  } catch (err) {
    serverReachable = false
  }

  const booking = {
    id: serverId ?? Date.now(),
    reference: serverRef ?? `WS-LOCAL-${String(Date.now()).slice(-6)}`,
    name: payload.name,
    email: payload.email,
    date: payload.date,
    time: payload.time,
    focus: payload.focus,
    notes: payload.notes,
    createdAt: serverCreatedAt ?? new Date().toISOString()
  }
  persistBooking(booking)
  submitted.value = booking
  form.name = ''
  form.email = ''
  form.date = ''
  form.time = ''
  form.focus = ''
  form.notes = ''
  submitting.value = false

  if (!serverReachable) {
    submitError.value = "We couldn't reach our booking system right now. Your request is saved locally — please try again in a moment."
  }
}

function bookAnother() {
  submitted.value = null
  scrollToId('book')
}

function scrollToId(id) {
  navOpen.value = false
  const el = document.getElementById(id)
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function formatDate(iso) {
  if (!iso) return ''
  const [y, m, d] = iso.split('-').map(Number)
  const dt = new Date(y, m - 1, d)
  return dt.toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })
}
</script>

<template>
  <div class="page">
    <header class="site-header" :class="{ 'is-open': navOpen }">
      <div class="container site-header__row">
        <a class="brand" href="#top" @click.prevent="scrollToId('top')" aria-label="Waystar Connect — home">
          <span class="brand__mark" aria-hidden="true">
            <svg viewBox="0 0 32 32" width="28" height="28">
              <path d="M4 22c4-2 6-6 12-6s8 4 12 6" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
              <circle cx="16" cy="10" r="3" fill="currentColor"/>
            </svg>
          </span>
          <span class="brand__name">Waystar <span>Connect</span></span>
        </a>

        <button
          class="nav-toggle"
          :aria-expanded="navOpen ? 'true' : 'false'"
          aria-controls="primary-nav"
          aria-label="Toggle menu"
          @click="navOpen = !navOpen"
        >
          <span></span><span></span><span></span>
        </button>

        <nav id="primary-nav" class="primary-nav" aria-label="Primary">
          <a href="#services" @click.prevent="scrollToId('services')">Services</a>
          <a href="#about" @click.prevent="scrollToId('about')">About us</a>
          <a href="#therapists" @click.prevent="scrollToId('therapists')">Therapists</a>
          <a href="#book" @click.prevent="scrollToId('book')">Book</a>
          <a class="btn btn--primary btn--sm" href="#book" @click.prevent="scrollToId('book')">Get started</a>
        </nav>
      </div>
    </header>

    <main id="main">
      <section id="top" class="hero">
        <div class="hero__decoration" aria-hidden="true">
          <span class="blob blob--1"></span>
          <span class="blob blob--2"></span>
        </div>
        <div class="container hero__grid">
          <div class="hero__copy">
            <p class="eyebrow">Online therapy · Licensed clinicians</p>
            <h1>Therapy that meets you <em>where you are.</em></h1>
            <p class="lede">
              Talk to a credentialed therapist from anywhere — evenings and weekends included.
              Real conversations, real progress, on your schedule.
            </p>
            <div class="hero__ctas">
              <a class="btn btn--primary btn--lg" href="#book" @click.prevent="scrollToId('book')">
                Book an appointment
                <span aria-hidden="true">→</span>
              </a>
              <a class="btn btn--ghost btn--lg" href="#about" @click.prevent="scrollToId('about')">Learn more</a>
            </div>
            <ul class="hero__trust">
              <li><strong>4.9★</strong> avg. session rating</li>
              <li><strong>200+</strong> licensed therapists</li>
              <li><strong>HIPAA</strong> compliant</li>
            </ul>
          </div>

          <div class="hero__panel" aria-hidden="true">
            <div class="panel-card panel-card--main">
              <div class="panel-card__top">
                <span class="dot dot--green"></span>
                <span>Next session</span>
              </div>
              <p class="panel-card__title">Thursday · 6:00 PM</p>
              <p class="panel-card__meta">with Dr. Amara Reyes</p>
              <div class="panel-card__row">
                <span class="chip">Video</span>
                <span class="chip chip--soft">Anxiety</span>
              </div>
            </div>
            <div class="panel-card panel-card--mini">
              <span class="panel-card__avatar">MC</span>
              <div>
                <p class="panel-card__title panel-card__title--sm">New message</p>
                <p class="panel-card__meta">"Looking forward to Thursday."</p>
              </div>
            </div>
            <div class="panel-card panel-card--pill">
              <span aria-hidden="true">✓</span> Insurance verified
            </div>
          </div>
        </div>
      </section>

      <section id="services" class="section section--soft">
        <div class="container">
          <header class="section__head">
            <p class="eyebrow">What we do</p>
            <h2>Care that fits the shape of your life</h2>
            <p class="section__sub">Choose the kind of support that actually matches where you are right now.</p>
          </header>
          <div class="cards">
            <article v-for="s in services" :key="s.title" class="card">
              <span class="card__icon" aria-hidden="true">{{ s.icon }}</span>
              <h3>{{ s.title }}</h3>
              <p>{{ s.body }}</p>
            </article>
          </div>
        </div>
      </section>

      <section id="about" class="section">
        <div class="container about">
          <div class="about__copy">
            <p class="eyebrow">About us</p>
            <h2>We built Waystar Connect to make great therapy reachable.</h2>
            <p>
              Waystar Connect is the online therapy arm of Waystar Royco's health network.
              Our mission is straightforward: pair every client with a licensed, vetted
              therapist within 48 hours — and make scheduling feel like the easy part.
            </p>
            <p>
              Every clinician on the platform is independently credentialed and supervised
              by our Clinical Standards Board. Sessions are end-to-end encrypted, fully
              private, and never used for advertising.
            </p>
            <ul class="trust-list">
              <li><span aria-hidden="true">✓</span> Licensed in all 50 states</li>
              <li><span aria-hidden="true">✓</span> Sessions covered by most major insurance</li>
              <li><span aria-hidden="true">✓</span> Encrypted video, no recording stored</li>
              <li><span aria-hidden="true">✓</span> Free 15-minute matching call</li>
            </ul>
          </div>
          <aside class="about__stats" aria-label="Highlights">
            <div class="stat">
              <p class="stat__num">48<span>hrs</span></p>
              <p class="stat__label">Average time to first session</p>
            </div>
            <div class="stat stat--accent">
              <p class="stat__num">94<span>%</span></p>
              <p class="stat__label">Clients report feeling heard after session 1</p>
            </div>
            <div class="stat">
              <p class="stat__num">200<span>+</span></p>
              <p class="stat__label">Vetted, licensed therapists</p>
            </div>
          </aside>
        </div>
      </section>

      <section id="therapists" class="section section--soft">
        <div class="container">
          <header class="section__head">
            <p class="eyebrow">Your therapists</p>
            <h2>A small sample of the team</h2>
            <p class="section__sub">Every Waystar Connect therapist is licensed, vetted, and supervised by our Clinical Standards Board.</p>
          </header>
          <div class="cards cards--people">
            <article v-for="t in therapists" :key="t.name" class="person">
              <div class="person__avatar" aria-hidden="true">{{ t.initials }}</div>
              <h3>{{ t.name }}</h3>
              <p class="person__cred">{{ t.credentials }}</p>
              <p class="person__focus">{{ t.focus }}</p>
              <p class="person__bio">{{ t.bio }}</p>
            </article>
          </div>
        </div>
      </section>

      <section id="book" class="section section--book">
        <div class="container booking">
          <div class="booking__intro">
            <p class="eyebrow">Book a session</p>
            <h2>Pick a time. We'll handle the rest.</h2>
            <p>
              Tell us a little about what's going on and when you're free. We'll match you with a
              therapist and confirm by email — usually within a few hours.
            </p>
            <ul class="booking__perks">
              <li><span aria-hidden="true">✓</span> Free 15-minute intro call included</li>
              <li><span aria-hidden="true">✓</span> Reschedule or cancel free up to 24h before</li>
              <li><span aria-hidden="true">✓</span> Most major insurance accepted</li>
            </ul>
            <p v-if="bookingsCount > 0" class="booking__counter">
              <span aria-hidden="true">●</span> {{ bookingsCount }} {{ bookingsCount === 1 ? 'session' : 'sessions' }} booked from this device
            </p>
          </div>

          <div class="booking__card">
            <div v-if="!submitted" class="form-wrap">
              <h3 class="form-title">Request your appointment</h3>
              <p class="form-sub">All fields are required unless marked optional.</p>

              <form class="form" novalidate @submit.prevent="submit" aria-describedby="form-instructions">
                <p id="form-instructions" class="visually-hidden">
                  Form for booking a therapy appointment. Required fields are marked.
                </p>

                <div class="field">
                  <label for="f-name">Full name</label>
                  <input
                    id="f-name"
                    v-model="form.name"
                    type="text"
                    autocomplete="name"
                    :aria-invalid="errors.name ? 'true' : 'false'"
                    :aria-describedby="errors.name ? 'err-name' : null"
                    required
                  >
                  <p v-if="errors.name" id="err-name" class="field__error">{{ errors.name }}</p>
                </div>

                <div class="field">
                  <label for="f-email">Email</label>
                  <input
                    id="f-email"
                    v-model="form.email"
                    type="email"
                    autocomplete="email"
                    inputmode="email"
                    :aria-invalid="errors.email ? 'true' : 'false'"
                    :aria-describedby="errors.email ? 'err-email' : null"
                    required
                  >
                  <p v-if="errors.email" id="err-email" class="field__error">{{ errors.email }}</p>
                </div>

                <div class="field-row">
                  <div class="field">
                    <label for="f-date">Preferred date</label>
                    <input
                      id="f-date"
                      v-model="form.date"
                      type="date"
                      :min="today"
                      :aria-invalid="errors.date ? 'true' : 'false'"
                      :aria-describedby="errors.date ? 'err-date' : null"
                      required
                    >
                    <p v-if="errors.date" id="err-date" class="field__error">{{ errors.date }}</p>
                  </div>

                  <div class="field">
                    <label for="f-time">Preferred time</label>
                    <select
                      id="f-time"
                      v-model="form.time"
                      :aria-invalid="errors.time ? 'true' : 'false'"
                      :aria-describedby="errors.time ? 'err-time' : null"
                      required
                    >
                      <option value="" disabled>Choose a time…</option>
                      <option v-for="t in timeSlots" :key="t" :value="t">{{ t }}</option>
                    </select>
                    <p v-if="errors.time" id="err-time" class="field__error">{{ errors.time }}</p>
                  </div>
                </div>

                <div class="field">
                  <label for="f-focus">What would you like to focus on?</label>
                  <select
                    id="f-focus"
                    v-model="form.focus"
                    :aria-invalid="errors.focus ? 'true' : 'false'"
                    :aria-describedby="errors.focus ? 'err-focus' : null"
                    required
                  >
                    <option value="" disabled>Choose a focus area…</option>
                    <option v-for="opt in focusOptions" :key="opt" :value="opt">{{ opt }}</option>
                  </select>
                  <p v-if="errors.focus" id="err-focus" class="field__error">{{ errors.focus }}</p>
                </div>

                <div class="field">
                  <label for="f-notes">Anything else? <span class="field__optional">(optional)</span></label>
                  <textarea
                    id="f-notes"
                    v-model="form.notes"
                    rows="3"
                    placeholder="Share anything you'd like your therapist to know in advance."
                    :aria-invalid="errors.notes ? 'true' : 'false'"
                    :aria-describedby="errors.notes ? 'err-notes' : null"
                  ></textarea>
                  <p v-if="errors.notes" id="err-notes" class="field__error">{{ errors.notes }}</p>
                </div>

                <button class="btn btn--primary btn--lg btn--block" type="submit" :disabled="submitting">
                  <span v-if="!submitting">Request appointment</span>
                  <span v-else class="btn__loading">
                    <span class="spinner" aria-hidden="true"></span>
                    Submitting…
                  </span>
                </button>

                <p v-if="submitError" class="form-error" role="alert">{{ submitError }}</p>

                <p class="form-fineprint">
                  By submitting, you agree to our terms and privacy notice. We'll never share your information.
                </p>
              </form>
            </div>

            <div v-else class="success" role="status" aria-live="polite">
              <div class="success__icon" aria-hidden="true">
                <svg viewBox="0 0 48 48" width="56" height="56">
                  <circle cx="24" cy="24" r="22" fill="none" stroke="currentColor" stroke-width="3"/>
                  <path d="M14 24l7 7 13-15" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
              </div>
              <h3>You're booked, {{ submitted.name.split(' ')[0] }}.</h3>
              <p class="success__lede">
                We've received your request for <strong>{{ formatDate(submitted.date) }} at {{ submitted.time }}</strong>.
                A confirmation is on its way to <strong>{{ submitted.email }}</strong>.
              </p>
              <dl class="success__details">
                <div><dt>Focus</dt><dd>{{ submitted.focus }}</dd></div>
                <div><dt>Reference</dt><dd>{{ submitted.reference }}</dd></div>
              </dl>
              <button class="btn btn--ghost" type="button" @click="bookAnother">Book another session</button>
            </div>
          </div>
        </div>
      </section>
    </main>

    <footer class="site-footer">
      <div class="container site-footer__grid">
        <div>
          <div class="brand brand--footer">
            <span class="brand__mark" aria-hidden="true">
              <svg viewBox="0 0 32 32" width="24" height="24">
                <path d="M4 22c4-2 6-6 12-6s8 4 12 6" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
                <circle cx="16" cy="10" r="3" fill="currentColor"/>
              </svg>
            </span>
            <span class="brand__name">Waystar <span>Connect</span></span>
          </div>
          <p class="site-footer__tag">Therapy that meets you where you are.</p>
        </div>
        <div>
          <h4>Care</h4>
          <ul>
            <li><a href="#services" @click.prevent="scrollToId('services')">Services</a></li>
            <li><a href="#therapists" @click.prevent="scrollToId('therapists')">Therapists</a></li>
            <li><a href="#book" @click.prevent="scrollToId('book')">Book a session</a></li>
          </ul>
        </div>
        <div>
          <h4>Company</h4>
          <ul>
            <li><a href="#about" @click.prevent="scrollToId('about')">About</a></li>
            <li><a href="#">Careers</a></li>
            <li><a href="#">Press</a></li>
          </ul>
        </div>
        <div>
          <h4>Contact</h4>
          <ul>
            <li><a href="mailto:hello@waystar-connect.dev">hello@waystar-connect.dev</a></li>
            <li><a href="tel:+18005550144">1-800-555-0144</a></li>
            <li>Mon–Sun, 7am–10pm ET</li>
          </ul>
        </div>
      </div>
      <div class="container site-footer__bottom">
        <p>© {{ year }} Waystar Connect, a Waystar Royco company. All rights reserved.</p>
        <ul class="site-footer__legal">
          <li><a href="#">Privacy</a></li>
          <li><a href="#">Terms</a></li>
          <li><a href="#">HIPAA notice</a></li>
        </ul>
      </div>
    </footer>
  </div>
</template>
