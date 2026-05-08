# Project brief — Waystar Connect

*Prepared by the turnaround consultancy, sign-off from the CTO and Board.*

## Goal

Ship a customer-facing online-therapy portal that:

1. Lets a new patient discover Waystar, complete intake, and book a session
   (video) with one of our existing therapists, end to end on the web.
2. Lets returning patients log in, manage upcoming sessions, message their
   therapist, and pay invoices.
3. Lets our therapists manage their caseloads (lighter scope — therapist
   tooling can be partial in the MVP).

The headline differentiator vs. BetterHelp / Talkspace / Cerebral / similar
is **real, credentialed therapists, available online**. We are *not*
becoming a faceless platform; we are extending Waystar's existing therapist
roster onto the web.

## Audience

Acquisition target is the under-30 demographic that is drifting to
online-first competitors. Marketing positioning will emphasise the
"real therapists" angle plus our post-breach security investments.

## Tech stack

- **Frontend**: web app (mobile-first, single-page). Pick a pragmatic
  framework — we are not picky on Vue vs. React vs. Svelte, pick what you
  ship fastest with. Hosting on the existing internal apache host.
- **Backend**: a thin REST shim over the existing Waystar internal systems
  (patient/therapist data, scheduling, payments). The shim is a separate
  project owned by the in-house team; you do not own the backend, but you
  may need to nudge them on missing endpoints.
- **Auth**: standard email + password + 2FA over the shim.

## Timeline

- Original: **six weeks** to MVP launch.
- *Post Q3 numbers update (week 2)*: pulled forward by two weeks to coincide
  with the investor presentation. **New target: four weeks.**

## What's in scope for MVP

- Landing page + marketing-driven discovery.
- New-patient intake flow + therapist-matching screen.
- Booking + video session start flow.
- Returning-patient login + session list + secure messaging.
- Payment (light: charge a card for a single session; subscriptions later).

## What's out of scope for MVP

- Group therapy.
- Full therapist scheduling tool — therapists can use the existing internal
  scheduling for v0; we'll integrate properly in v0.5.
- Mobile native apps. Mobile-friendly web is enough for MVP.
- The clinical EHR side. That stays where it is.

## Stakeholders

- **Product owner**: Dr. M. Roy, CTO.
- **Consultancy PM**: see *Useful contacts.md*.
- **In-house engineering** (backend shim): see *Useful contacts.md*.
- **Frontend**: you.

## Definition of done

Public launch announcement on LinkedIn, the apache build serving the
patient-facing flow without errors, the therapist roster visible and
bookable. Demo to the board the same week.
