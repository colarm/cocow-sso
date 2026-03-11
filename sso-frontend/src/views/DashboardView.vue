<template>
  <AppShell>
    <!-- Welcome banner -->
    <section class="welcome-card">
      <div class="avatar">{{ avatarInitial }}</div>
      <div>
        <h2 class="welcome-title">Welcome back, <strong>{{ store.user?.username }}</strong>!</h2>
        <p class="welcome-sub">You are authenticated via Cocow SSO.</p>
      </div>
    </section>

    <!-- Account info -->
    <section class="info-card">
      <h3 class="info-title">Account Information</h3>
      <table class="info-table">
        <tbody>
          <tr><th>User ID</th><td>{{ store.user?.id }}</td></tr>
          <tr><th>Username</th><td>{{ store.user?.username }}</td></tr>
          <tr><th>Email</th><td>{{ store.user?.email }}</td></tr>
          <tr>
            <th>Role</th>
            <td><span class="badge badge-purple">{{ store.user?.role }}</span></td>
          </tr>
          <tr>
            <th>Account Status</th>
            <td>
              <span class="badge" :class="store.user?.enabled ? 'badge-green' : 'badge-red'">
                {{ store.user?.enabled ? 'Active' : 'Disabled' }}
              </span>
            </td>
          </tr>
          <tr>
            <th>Account Locked</th>
            <td>
              <span class="badge" :class="store.user?.locked ? 'badge-red' : 'badge-green'">
                {{ store.user?.locked ? 'Locked' : 'Normal' }}
              </span>
            </td>
          </tr>
          <tr><th>Created At</th><td>{{ formattedDate }}</td></tr>
        </tbody>
      </table>
    </section>

    <!-- Session info -->
    <section class="info-card">
      <h3 class="info-title">Session</h3>
      <p class="session-note">
        Your session is maintained via a secure <code>HttpOnly</code> cookie.
        Signing out will invalidate your server-side session immediately.
        You can manage your profile and password in
        <router-link :to="{ name: 'Settings' }">Settings</router-link>.
      </p>
    </section>
  </AppShell>
</template>

<script setup>
import { computed } from 'vue'
import { useAuthStore } from '../stores/auth.js'
import AppShell from '../components/AppShell.vue'

const store = useAuthStore()

const avatarInitial = computed(() =>
  (store.user?.username ?? '?').charAt(0).toUpperCase()
)

const formattedDate = computed(() => {
  if (!store.user?.createdAt) return '—'
  return new Date(store.user.createdAt).toLocaleString()
})
</script>

<style scoped>
/* ── Welcome card ───────────────────────────────────────────────────────── */
.welcome-card {
  background: linear-gradient(135deg, var(--primary) 0%, #6366f1 100%);
  border-radius: var(--radius);
  padding: 2rem;
  display: flex;
  align-items: center;
  gap: 1.25rem;
  color: #fff;
}
.avatar {
  width: 56px;
  height: 56px;
  border-radius: 50%;
  background: rgba(255,255,255,0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.6rem;
  font-weight: 700;
  flex-shrink: 0;
}
.welcome-title { margin: 0 0 0.25rem; font-size: 1.2rem; }
.welcome-sub   { margin: 0; opacity: 0.85; font-size: 0.9rem; }

/* ── Info card ──────────────────────────────────────────────────────────── */
.info-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem;
}
.info-title {
  margin: 0 0 1rem;
  font-size: 1rem;
  font-weight: 600;
  color: var(--text);
}
.info-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
.info-table th {
  text-align: left;
  padding: 0.55rem 1rem 0.55rem 0;
  color: var(--text-muted);
  font-weight: 500;
  width: 38%;
  white-space: nowrap;
}
.info-table td { padding: 0.55rem 0; color: var(--text); }
.info-table tr + tr th,
.info-table tr + tr td { border-top: 1px solid var(--border); }

/* ── Badges ─────────────────────────────────────────────────────────────── */
.badge {
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 600;
}
.badge-green  { background: #dcfce7; color: #15803d; }
.badge-red    { background: #fee2e2; color: #991b1b; }
.badge-purple { background: #ede9fe; color: #5b21b6; }

/* ── Session note ────────────────────────────────────────────────────────── */
.session-note {
  margin: 0;
  font-size: 0.88rem;
  color: var(--text-muted);
  line-height: 1.6;
}
.session-note a { color: var(--primary); text-decoration: none; font-weight: 500; }
.session-note a:hover { text-decoration: underline; }
.session-note code {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.1rem 0.35rem;
  font-size: 0.82rem;
}
</style>

<style scoped>
.dashboard-page {
  min-height: 100vh;
  background: var(--bg);
  display: flex;
  flex-direction: column;
}

/* ── Top bar ────────────────────────────────────────────────────────────── */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 2rem;
  height: 60px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 10;
}
.topbar-brand {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 700;
  font-size: 1.1rem;
  color: var(--text);
}
.brand-icon { font-size: 1.3rem; }

/* ── Main ───────────────────────────────────────────────────────────────── */
.dashboard-main {
  flex: 1;
  max-width: 720px;
  width: 100%;
  margin: 2.5rem auto;
  padding: 0 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

/* ── Welcome card ───────────────────────────────────────────────────────── */
.welcome-card {
  background: linear-gradient(135deg, var(--primary) 0%, #6366f1 100%);
  border-radius: var(--radius);
  padding: 2rem;
  display: flex;
  align-items: center;
  gap: 1.25rem;
  color: #fff;
}
.avatar {
  width: 56px;
  height: 56px;
  border-radius: 50%;
  background: rgba(255,255,255,0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.6rem;
  font-weight: 700;
  flex-shrink: 0;
}
.welcome-title { margin: 0 0 0.25rem; font-size: 1.2rem; }
.welcome-sub   { margin: 0; opacity: 0.85; font-size: 0.9rem; }

/* ── Info card ──────────────────────────────────────────────────────────── */
.info-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem;
}
.info-title {
  margin: 0 0 1rem;
  font-size: 1rem;
  font-weight: 600;
  color: var(--text);
}
.info-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}
.info-table th {
  text-align: left;
  padding: 0.55rem 1rem 0.55rem 0;
  color: var(--text-muted);
  font-weight: 500;
  width: 38%;
  white-space: nowrap;
}
.info-table td {
  padding: 0.55rem 0;
  color: var(--text);
  word-break: break-all;
}
.info-table tr + tr th,
.info-table tr + tr td {
  border-top: 1px solid var(--border);
}

/* ── Badges ─────────────────────────────────────────────────────────────── */
.badge {
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 600;
}
.badge-green { background: #dcfce7; color: #15803d; }
.badge-red   { background: #fee2e2; color: #991b1b; }

/* ── Session note ────────────────────────────────────────────────────────── */
.session-note {
  margin: 0;
  font-size: 0.88rem;
  color: var(--text-muted);
  line-height: 1.6;
}
.session-note code {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.1rem 0.35rem;
  font-size: 0.82rem;
}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
.btn-outline {
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  padding: 0.45rem 1rem;
  border-radius: var(--radius);
  font-size: 0.88rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  transition: border-color 0.2s, color 0.2s;
}
.btn-outline:hover:not(:disabled) {
  border-color: #ef4444;
  color: #ef4444;
}
.btn-outline:disabled { opacity: 0.6; cursor: not-allowed; }

.spinner-sm {
  width: 14px; height: 14px;
  border: 2px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  display: inline-block;
}
</style>
