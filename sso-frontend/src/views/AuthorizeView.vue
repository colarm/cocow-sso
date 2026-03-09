<template>
  <div class="auth-page">

    <!-- ── State: verifying ──────────────────────────────────────────────── -->
    <div v-if="verifying" class="state-card">
      <div class="spinner-lg"></div>
      <p class="state-msg">Verifying application…</p>
    </div>

    <!-- ── State: invalid client ─────────────────────────────────────────── -->
    <div v-else-if="clientInvalid" class="state-card state-error">
      <span class="state-icon">⛔</span>
      <h2 class="state-title">Unknown Application</h2>
      <p class="state-body">
        The client <code>{{ oidc.params?.clientId }}</code> is not registered
        in this SSO server. This authorization request is invalid.
      </p>
      <div class="danger-banner">
        <span class="danger-icon">⚠️</span>
        <div>
          <strong>Potential security risk</strong>
          <p>
            This application is not recognized and may be attempting to steal your
            account credentials or access your data without authorization.
            Do <em>not</em> proceed — close this page or go back to safety.
          </p>
        </div>
      </div>
      <button class="btn btn-deny" @click="handleInvalidBack">Go to Dashboard</button>
    </div>

    <!-- ── State: consent screen ─────────────────────────────────────────── -->
    <div v-else class="auth-card authorize-card">

      <!-- Client / app branding ------------------------------------------ -->
      <div class="brand">
        <div class="app-icon">{{ appInitial }}</div>
        <h1 class="brand-name">{{ clientName }}</h1>
        <p class="brand-sub">wants access to your Cocow account</p>
        <p class="account-hint">Signed in as <strong>{{ store.user?.username }}</strong></p>
      </div>

      <!-- Error banner ----------------------------------------------------- -->
      <div v-if="apiError" class="alert alert-error">{{ apiError }}</div>

      <!-- Scope list ------------------------------------------------------- -->
      <div class="scope-section">
        <p class="scope-heading">This application will be able to:</p>
        <ul class="scope-list">
          <li v-for="s in scopeItems" :key="s.id" class="scope-item">
            <span class="scope-icon">{{ s.icon }}</span>
            <div>
              <span class="scope-label">{{ s.label }}</span>
              <span class="scope-desc">{{ s.desc }}</span>
            </div>
          </li>
        </ul>
      </div>

      <!-- OAuth details (collapsible) -------------------------------------- -->
      <details class="oauth-details">
        <summary>Technical details</summary>
        <table class="detail-table">
          <tr><th>Client ID</th><td><code>{{ oidc.params?.clientId }}</code></td></tr>
          <tr><th>Redirect URI</th><td class="break-all"><code>{{ oidc.params?.redirectUri }}</code></td></tr>
          <tr><th>Scopes</th><td><code>{{ oidc.params?.scope }}</code></td></tr>
          <tr><th>Response type</th><td><code>{{ oidc.params?.responseType }}</code></td></tr>
        </table>
      </details>

      <!-- Actions ---------------------------------------------------------- -->
      <div class="action-row">
        <button class="btn btn-deny" :disabled="busy" @click="handleDeny">Deny</button>
        <button class="btn btn-approve" :disabled="busy" @click="handleApprove">
          <span v-if="busy" class="spinner"></span>
          <span>{{ busy ? 'Authorizing…' : 'Allow Access' }}</span>
        </button>
      </div>

      <p class="cancel-note">
        Denying will redirect back to
        <span class="redirect-host">{{ redirectHost }}</span>
        with an error.
      </p>
    </div>

  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth.js'
import { useOidcStore } from '../stores/oidc.js'
import { clientApi, oauthApi } from '../api/auth.js'

const store  = useAuthStore()
const oidc   = useOidcStore()
const router = useRouter()

const clientName    = ref(oidc.params?.clientId ?? 'Unknown App')
const apiError      = ref(null)
const clientInvalid = ref(false)   // true when client_id is not recognised
const verifying     = ref(true)    // true until client verification finishes
const busy          = ref(false)

// ── Derived ──────────────────────────────────────────────────────────────
const appInitial   = computed(() => clientName.value.charAt(0).toUpperCase())
const redirectHost = computed(() => {
  try { return new URL(oidc.params?.redirectUri ?? '').hostname }
  catch { return oidc.params?.redirectUri ?? '' }
})

/** Map raw scope strings to human-readable descriptions */
const SCOPE_MAP = {
  openid:  { icon: '🆔', label: 'Know your identity',       desc: 'Verify who you are via OpenID Connect' },
  profile: { icon: '👤', label: 'Read your profile',        desc: 'Access your username and display name' },
  email:   { icon: '📧', label: 'Read your email address',  desc: 'Access your registered email address' },
  read:    { icon: '📖', label: 'Read your data',           desc: 'Read data on your behalf' },
  write:   { icon: '✏️',  label: 'Write your data',          desc: 'Create and update data on your behalf' },
  offline_access: { icon: '🔄', label: 'Offline access', desc: 'Access your data when you are not online' },
}

const scopeItems = computed(() =>
  (oidc.params?.scope ?? 'openid').split(/\s+/).map((id) => ({
    id,
    icon:  SCOPE_MAP[id]?.icon  ?? '🔑',
    label: SCOPE_MAP[id]?.label ?? id,
    desc:  SCOPE_MAP[id]?.desc  ?? '',
  }))
)

// ── Lifecycle ─────────────────────────────────────────────────────────────
onMounted(async () => {
  if (!oidc.hasPending) {
    router.replace({ name: 'Dashboard' })
    return
  }
  // Verify the client_id exists and fetch its display name.
  // A 404 means the client is not registered — block the consent flow.
  try {
    const res = await clientApi.getClientInfo(oidc.params.clientId)
    if (res.data?.clientName) clientName.value = res.data.clientName
  } catch (e) {
    const status = e.response?.status
    if (status === 404) {
      clientInvalid.value = true
    } else {
      // Network / server error — warn but don't hard-block
      apiError.value = 'Could not verify the client application. Proceed with caution.'
    }
  } finally {
    verifying.value = false
  }
})

// ── Actions ───────────────────────────────────────────────────────────────
async function handleApprove() {
  busy.value     = true
  apiError.value = null
  try {
    const res = await oauthApi.approve(oidc.params)
    const target = res.data?.redirectUri ?? null

    if (target) {
      oidc.clear()
      window.location.href = target  // hard navigate — leaves the SSO SPA
    } else {
      apiError.value = 'Authorization succeeded but no redirect URI was returned.'
    }
  } catch (e) {
    const msg = e.response?.data?.message ?? e.response?.data ?? e.message
    apiError.value = `Authorization failed: ${msg}`
  } finally {
    busy.value = false
  }
}

function handleDeny() {
  const url = oauthApi.denyRedirectUrl(oidc.params.redirectUri, oidc.params.state)
  oidc.clear()
  window.location.href = url
}

/** Called when client_id was invalid — just go home, don't redirect to the suspect URI */
function handleInvalidBack() {
  oidc.clear()
  router.replace({ name: 'Dashboard' })
}
</script>

<style scoped>
@import '../assets/auth.css';

.authorize-card { max-width: 460px; }

/* ── App icon ──────────────────────────────────────────────────────────── */
.app-icon {
  width: 64px;
  height: 64px;
  border-radius: 16px;
  background: linear-gradient(135deg, var(--primary) 0%, #6366f1 100%);
  color: #fff;
  font-size: 1.8rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 0.75rem;
}

.account-hint {
  margin: 0.35rem 0 0;
  font-size: 0.8rem;
  color: var(--text-muted);
}

/* ── Scope list ─────────────────────────────────────────────────────────── */
.scope-section {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) - 2px);
  padding: 1rem 1.25rem;
  margin-bottom: 0.75rem;
}
.scope-heading {
  margin: 0 0 0.75rem;
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.scope-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}
.scope-item {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  font-size: 0.9rem;
}
.scope-icon { font-size: 1.1rem; line-height: 1.4; flex-shrink: 0; }
.scope-label { display: block; font-weight: 500; color: var(--text); }
.scope-desc  { display: block; font-size: 0.78rem; color: var(--text-muted); }

/* ── OAuth details ──────────────────────────────────────────────────────── */
.oauth-details {
  font-size: 0.82rem;
  color: var(--text-muted);
  margin-bottom: 0.75rem;
}
.oauth-details summary {
  cursor: pointer;
  user-select: none;
  padding: 0.2rem 0;
  color: var(--text-muted);
}
.detail-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 0.5rem;
}
.detail-table th {
  text-align: left;
  padding: 0.3rem 0.75rem 0.3rem 0;
  font-weight: 500;
  white-space: nowrap;
  color: var(--text-muted);
  width: 38%;
}
.detail-table td { padding: 0.3rem 0; }
.detail-table code {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 0.1rem 0.35rem;
  font-size: 0.78rem;
}
.break-all code { word-break: break-all; }

/* ── Action row ─────────────────────────────────────────────────────────── */
.action-row {
  display: flex;
  gap: 0.75rem;
  margin-top: 0.5rem;
}
.action-row .btn { flex: 1; }

.btn-deny {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text-muted);
  padding: 0.7rem;
  border-radius: calc(var(--radius) - 2px);
  font-size: 0.95rem;
  font-weight: 600;
  cursor: pointer;
  transition: border-color 0.2s, color 0.2s;
}
.btn-deny:hover:not(:disabled) {
  border-color: #ef4444;
  color: #ef4444;
}
.btn-deny:disabled { opacity: 0.6; cursor: not-allowed; }

.btn-approve {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  background: var(--primary);
  color: #fff;
  border: none;
  padding: 0.7rem;
  border-radius: calc(var(--radius) - 2px);
  font-size: 0.95rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.2s, opacity 0.2s;
}
.btn-approve:hover:not(:disabled) { background: var(--primary-hover); }
.btn-approve:disabled { opacity: 0.6; cursor: not-allowed; }

/* ── Cancel note ─────────────────────────────────────────────────────────── */
.cancel-note {
  margin: 0.75rem 0 0;
  font-size: 0.78rem;
  color: var(--text-muted);
  text-align: center;
}
.redirect-host {
  font-family: monospace;
  font-size: 0.78rem;
  background: var(--bg);
  padding: 0.1rem 0.3rem;
  border: 1px solid var(--border);
  border-radius: 3px;
}

/* ── Loading / error state cards ─────────────────────────────────────────── */
.state-card {
  max-width: 400px;
  width: 100%;
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 3rem 2rem;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
}

.state-error { border-color: #fca5a5; }

.state-icon {
  font-size: 3rem;
  line-height: 1;
}

.state-title {
  margin: 0;
  font-size: 1.2rem;
  font-weight: 700;
  color: var(--text);
}

.state-body {
  margin: 0;
  font-size: 0.88rem;
  color: var(--text-muted);
  line-height: 1.6;
}
.state-body code {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 0.1rem 0.35rem;
  font-size: 0.82rem;
}

/* ── Danger warning banner ──────────────────────────────────────────────── */
.danger-banner {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  background: #fff1f2;
  border: 1px solid #fca5a5;
  border-radius: calc(var(--radius) - 4px);
  padding: 0.9rem 1rem;
  text-align: left;
  color: #b91c1c;
}
.danger-banner strong {
  display: block;
  font-size: 0.9rem;
  margin-bottom: 0.3rem;
}
.danger-banner p {
  margin: 0;
  font-size: 0.82rem;
  line-height: 1.55;
  color: #9f1239;
}
.danger-icon {
  font-size: 1.4rem;
  flex-shrink: 0;
  line-height: 1.3;
}

.state-msg {
  margin: 0;
  font-size: 0.9rem;
  color: var(--text-muted);
}

/* ── Spinner (large, for loading state) ──────────────────────────────────── */
.spinner-lg {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border);
  border-top-color: var(--primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
