<template>
  <div class="shell">
    <header class="topbar">
      <div class="topbar-brand">
        <span class="brand-icon">🔐</span>
        <span class="brand-name">Cocow SSO</span>
      </div>

      <nav class="topbar-nav">
        <router-link :to="{ name: 'Dashboard' }" class="nav-link">Dashboard</router-link>
        <router-link :to="{ name: 'Settings' }" class="nav-link">Settings</router-link>
        <router-link v-if="hasClientAccess" :to="{ name: 'Clients' }" class="nav-link">Clients</router-link>
        <router-link v-if="isAdmin" :to="{ name: 'Admin' }" class="nav-link">Admin</router-link>
      </nav>

      <div class="topbar-right">
        <span class="user-badge">
          <span class="user-initial">{{ userInitial }}</span>
          <span class="user-name">{{ store.user?.username }}</span>
          <span v-if="store.user?.role" class="role-chip" :class="roleClass">{{ store.user.role }}</span>
        </span>
        <button class="btn-signout" :disabled="store.loading" @click="handleLogout">
          <span v-if="store.loading" class="spinner-sm"></span>
          <span>{{ store.loading ? '…' : 'Sign Out' }}</span>
        </button>
      </div>
    </header>

    <main class="shell-main">
      <slot />
    </main>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth.js'

const store = useAuthStore()
const router = useRouter()

const userInitial = computed(() => (store.user?.username ?? '?').charAt(0).toUpperCase())

const hasClientAccess = computed(() =>
  store.user?.role === 'ADMIN' || store.user?.role === 'CLIENT_ADMIN'
)

const isAdmin = computed(() => store.user?.role === 'ADMIN')

const roleClass = computed(() => ({
  'role-admin':        store.user?.role === 'ADMIN',
  'role-client-admin': store.user?.role === 'CLIENT_ADMIN',
  'role-user':         store.user?.role === 'USER',
}))

async function handleLogout() {
  await store.logout()
  router.push({ name: 'Login' })
}
</script>

<style scoped>
.shell {
  min-height: 100vh;
  background: var(--bg);
  display: flex;
  flex-direction: column;
}

/* ── Topbar ─────────────────────────────────────────────────────────────── */
.topbar {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0 1.75rem;
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
  gap: 0.45rem;
  font-weight: 700;
  font-size: 1rem;
  color: var(--text);
  white-space: nowrap;
  flex-shrink: 0;
}
.brand-icon { font-size: 1.15rem; }

/* ── Nav ────────────────────────────────────────────────────────────────── */
.topbar-nav {
  display: flex;
  align-items: center;
  gap: 0.1rem;
  flex: 1;
}
.nav-link {
  padding: 0.32rem 0.8rem;
  border-radius: 6px;
  font-size: 0.88rem;
  font-weight: 500;
  color: var(--text-muted);
  text-decoration: none;
  transition: background 0.15s, color 0.15s;
}
.nav-link:hover { background: var(--bg); color: var(--text); }
.nav-link.router-link-active {
  background: var(--bg);
  color: var(--primary);
  font-weight: 600;
}

/* ── Right side ─────────────────────────────────────────────────────────── */
.topbar-right {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-left: auto;
  flex-shrink: 0;
}

.user-badge {
  display: flex;
  align-items: center;
  gap: 0.45rem;
}
.user-initial {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: var(--primary);
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.82rem;
  font-weight: 700;
  flex-shrink: 0;
}
.user-name {
  font-size: 0.85rem;
  color: var(--text);
  max-width: 100px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.role-chip {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.15rem 0.5rem;
  border-radius: 999px;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}
.role-admin        { background: #fef3c7; color: #92400e; }
.role-client-admin { background: #ede9fe; color: #5b21b6; }
.role-user         { background: var(--bg); color: var(--text-muted); border: 1px solid var(--border); }

.btn-signout {
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  padding: 0.38rem 0.85rem;
  border-radius: var(--radius);
  font-size: 0.83rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.35rem;
  white-space: nowrap;
  transition: border-color 0.2s, color 0.2s;
}
.btn-signout:hover:not(:disabled) { border-color: #ef4444; color: #ef4444; }
.btn-signout:disabled { opacity: 0.55; cursor: not-allowed; }

/* ── Main content ───────────────────────────────────────────────────────── */
.shell-main {
  flex: 1;
  max-width: 800px;
  width: 100%;
  margin: 2.5rem auto;
  padding: 0 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

/* ── Spinner ────────────────────────────────────────────────────────────── */
.spinner-sm {
  width: 12px; height: 12px;
  border: 2px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  display: inline-block;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
