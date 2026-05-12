// Waystar Connect — entry point.
// MVP: render landing, hand off to booking flow once the backend shim is up.

import { createApp, h } from 'vue'

const Landing = {
  setup() {
    return () => h('main', [
      h('h1', 'Waystar Connect'),
      h('p', 'Therapy that meets you where you are.'),
      h('a', { class: 'cta', href: '/book' }, 'Book a session'),
    ])
  }
}

createApp(Landing).mount('#app')
