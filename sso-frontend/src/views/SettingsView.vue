<template>
  <AppShell>
    <div class="page-header">
      <h2 class="page-title">Account Settings</h2>
    </div>

    <!-- Tab navigation -->
    <div class="tab-strip">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        class="tab-btn"
        :class="{ active: activeTab === tab.id, danger: tab.id === 'danger' && activeTab === tab.id }"
        @click="activeTab = tab.id; clearMessages()"
      >
        {{ tab.label }}
      </button>
    </div>

    <!-- ── Profile ─────────────────────────────────────────────────────── -->
    <section v-if="activeTab === 'profile'" class="settings-card">
      <h3 class="card-title">Profile Information</h3>

      <div v-if="profileMsg" class="alert" :class="profileMsg.ok ? 'alert-success' : 'alert-error'">
        {{ profileMsg.text }}
      </div>

      <form @submit.prevent="handleUpdateProfile" novalidate>
        <div class="form-group">
          <label for="s-username">Username</label>
          <input
            id="s-username"
            v-model.trim="profile.username"
            type="text"
            placeholder="Username"
            autocomplete="username"
            :class="{ error: pv.username }"
            @input="pv.username = ''"
          />
          <span v-if="pv.username" class="field-error">{{ pv.username }}</span>
        </div>

        <div class="form-group">
          <label for="s-email">Email</label>
          <input
            id="s-email"
            v-model.trim="profile.email"
            type="email"
            placeholder="you@example.com"
            autocomplete="email"
            :class="{ error: pv.email }"
            @input="pv.email = ''"
          />
          <span v-if="pv.email" class="field-error">{{ pv.email }}</span>
        </div>

        <button type="submit" class="btn btn-primary" :disabled="store.loading">
          <span v-if="store.loading" class="spinner"></span>
          Save Changes
        </button>
      </form>
    </section>

    <!-- ── Security ───────────────────────────────────────────────────── -->
    <section v-if="activeTab === 'security'" class="settings-card">
      <h3 class="card-title">Change Password</h3>

      <div v-if="pwMsg" class="alert" :class="pwMsg.ok ? 'alert-success' : 'alert-error'">
        {{ pwMsg.text }}
      </div>

      <form @submit.prevent="handleChangePassword" novalidate>
        <div class="form-group">
          <label for="s-old-pw">Current Password</label>
          <div class="input-wrapper">
            <input
              id="s-old-pw"
              v-model="pw.old"
              :type="show.old ? 'text' : 'password'"
              placeholder="Current password"
              autocomplete="current-password"
              :class="{ error: sv.old }"
              @input="sv.old = ''"
            />
            <button type="button" class="toggle-pw" @click="show.old = !show.old" tabindex="-1">
              {{ show.old ? '🙈' : '👁️' }}
            </button>
          </div>
          <span v-if="sv.old" class="field-error">{{ sv.old }}</span>
        </div>

        <div class="form-group">
          <label for="s-new-pw">New Password</label>
          <div class="input-wrapper">
            <input
              id="s-new-pw"
              v-model="pw.newPw"
              :type="show.newPw ? 'text' : 'password'"
              placeholder="New password (min. 8 characters)"
              autocomplete="new-password"
              :class="{ error: sv.newPw }"
              @input="sv.newPw = ''"
            />
            <button type="button" class="toggle-pw" @click="show.newPw = !show.newPw" tabindex="-1">
              {{ show.newPw ? '🙈' : '👁️' }}
            </button>
          </div>
          <span v-if="sv.newPw" class="field-error">{{ sv.newPw }}</span>
        </div>

        <div class="form-group">
          <label for="s-confirm-pw">Confirm New Password</label>
          <div class="input-wrapper">
            <input
              id="s-confirm-pw"
              v-model="pw.confirm"
              :type="show.confirm ? 'text' : 'password'"
              placeholder="Repeat new password"
              autocomplete="new-password"
              :class="{ error: sv.confirm }"
              @input="sv.confirm = ''"
            />
            <button type="button" class="toggle-pw" @click="show.confirm = !show.confirm" tabindex="-1">
              {{ show.confirm ? '🙈' : '👁️' }}
            </button>
          </div>
          <span v-if="sv.confirm" class="field-error">{{ sv.confirm }}</span>
        </div>

        <button type="submit" class="btn btn-primary" :disabled="store.loading">
          <span v-if="store.loading" class="spinner"></span>
          Change Password
        </button>
      </form>
    </section>

    <!-- ── Danger Zone ─────────────────────────────────────────────────── -->
    <section v-if="activeTab === 'danger'" class="settings-card danger-card">
      <h3 class="card-title">Danger Zone</h3>
      <p class="danger-desc">
        Permanently delete your account and all associated data.
        <strong>This action cannot be undone.</strong>
      </p>

      <div v-if="deleteMsg" class="alert alert-error">{{ deleteMsg }}</div>

      <form @submit.prevent="handleDeleteAccount" novalidate>
        <div class="form-group">
          <label for="s-del-pw">Confirm your password to continue</label>
          <div class="input-wrapper">
            <input
              id="s-del-pw"
              v-model="delPassword"
              :type="show.del ? 'text' : 'password'"
              placeholder="Enter your current password"
              autocomplete="current-password"
            />
            <button type="button" class="toggle-pw" @click="show.del = !show.del" tabindex="-1">
              {{ show.del ? '🙈' : '👁️' }}
            </button>
          </div>
        </div>

        <button type="submit" class="btn btn-danger" :disabled="store.loading || !delPassword">
          <span v-if="store.loading" class="spinner spinner-red"></span>
          Delete My Account Permanently
        </button>
      </form>
    </section>
  </AppShell>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth.js'
import AppShell from '../components/AppShell.vue'

const store  = useAuthStore()
const router = useRouter()

const tabs = [
  { id: 'profile',  label: 'Profile'    },
  { id: 'security', label: 'Security'   },
  { id: 'danger',   label: 'Danger Zone'},
]
const activeTab = ref('profile')

function clearMessages() {
  profileMsg.value = null
  pwMsg.value      = null
  deleteMsg.value  = ''
}

// ── Profile ──────────────────────────────────────────────────────────────
const profile    = reactive({ username: '', email: '' })
const pv         = reactive({ username: '', email: '' })
const profileMsg = ref(null)

onMounted(() => {
  profile.username = store.user?.username ?? ''
  profile.email    = store.user?.email    ?? ''
})

async function handleUpdateProfile() {
  pv.username = ''
  pv.email    = ''
  profileMsg.value = null
  if (!profile.username) { pv.username = 'Username is required'; return }
  if (!profile.email)    { pv.email    = 'Email is required'; return }

  const result = await store.updateInfo(profile.username, profile.email)
  profileMsg.value = result.success
    ? { ok: true,  text: 'Profile updated successfully.' }
    : { ok: false, text: store.error }
}

// ── Security ─────────────────────────────────────────────────────────────
const pw    = reactive({ old: '', newPw: '', confirm: '' })
const sv    = reactive({ old: '', newPw: '', confirm: '' })
const show  = reactive({ old: false, newPw: false, confirm: false, del: false })
const pwMsg = ref(null)

async function handleChangePassword() {
  sv.old = ''; sv.newPw = ''; sv.confirm = ''
  pwMsg.value = null

  if (!pw.old)                      { sv.old    = 'Current password is required'; return }
  if (!pw.newPw)                    { sv.newPw  = 'New password is required'; return }
  if (pw.newPw.length < 8)          { sv.newPw  = 'Password must be at least 8 characters'; return }
  if (pw.newPw !== pw.confirm)      { sv.confirm = 'Passwords do not match'; return }

  const result = await store.changePassword(pw.old, pw.newPw)
  if (result.success) {
    pwMsg.value = { ok: true, text: 'Password changed successfully.' }
    pw.old = ''; pw.newPw = ''; pw.confirm = ''
  } else {
    pwMsg.value = { ok: false, text: store.error }
  }
}

// ── Danger Zone ───────────────────────────────────────────────────────────
const delPassword = ref('')
const deleteMsg   = ref('')

async function handleDeleteAccount() {
  deleteMsg.value = ''
  const result = await store.deleteAccount(delPassword.value)
  if (result.success) {
    router.push({ name: 'Login' })
  } else {
    deleteMsg.value = store.error
  }
}
</script>

<style scoped>
.page-header { }
.page-title {
  margin: 0;
  font-size: 1.35rem;
  font-weight: 700;
  color: var(--text);
}

/* ── Tab strip ──────────────────────────────────────────────────────────── */
.tab-strip {
  display: flex;
  gap: 0.25rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0;
}
.tab-btn {
  padding: 0.55rem 1.1rem;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  margin-bottom: -1px;
  transition: color 0.15s, border-color 0.15s;
}
.tab-btn:hover { color: var(--text); }
.tab-btn.active {
  color: var(--primary);
  border-bottom-color: var(--primary);
  font-weight: 600;
}
.tab-btn.danger.active {
  color: #dc2626;
  border-bottom-color: #dc2626;
}

/* ── Settings card ──────────────────────────────────────────────────────── */
.settings-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.75rem;
}
.danger-card { border-color: #fca5a5; }

.card-title {
  margin: 0 0 1.25rem;
  font-size: 1rem;
  font-weight: 600;
  color: var(--text);
}

.danger-desc {
  font-size: 0.9rem;
  color: var(--text-muted);
  margin: 0 0 1.25rem;
  line-height: 1.6;
}

/* ── Form ───────────────────────────────────────────────────────────────── */
form { display: flex; flex-direction: column; gap: 1.1rem; }

.form-group { display: flex; flex-direction: column; gap: 0.35rem; }

label { font-size: 0.875rem; font-weight: 500; color: var(--text); }

input[type='text'],
input[type='email'],
input[type='password'] {
  width: 100%;
  padding: 0.6rem 0.9rem;
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) - 2px);
  background: var(--bg);
  color: var(--text);
  font-size: 0.95rem;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  box-sizing: border-box;
}
input:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
}
input.error { border-color: #ef4444; }

.input-wrapper { position: relative; }
.input-wrapper input { padding-right: 2.6rem; }
.toggle-pw {
  position: absolute;
  right: 0.6rem;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  cursor: pointer;
  font-size: 1rem;
  padding: 0.2rem;
  color: var(--text-muted);
}

.field-error { font-size: 0.78rem; color: #ef4444; }

/* ── Alert ──────────────────────────────────────────────────────────────── */
.alert {
  border-radius: calc(var(--radius) - 2px);
  padding: 0.7rem 1rem;
  font-size: 0.875rem;
}
.alert-success { background: #dcfce7; border: 1px solid #86efac; color: #15803d; }
.alert-error   { background: #fee2e2; border: 1px solid #fca5a5; color: #b91c1c; }

/* ── Buttons ────────────────────────────────────────────────────────────── */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.65rem 1.25rem;
  border: none;
  border-radius: calc(var(--radius) - 2px);
  font-size: 0.92rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.2s, opacity 0.2s;
  width: fit-content;
}
.btn:disabled { opacity: 0.6; cursor: not-allowed; }

.btn-primary { background: var(--primary); color: #fff; }
.btn-primary:hover:not(:disabled) { background: var(--primary-hover); }

.btn-danger { background: #dc2626; color: #fff; }
.btn-danger:hover:not(:disabled) { background: #b91c1c; }

/* ── Spinner ────────────────────────────────────────────────────────────── */
.spinner {
  width: 15px; height: 15px;
  border: 2px solid rgba(255,255,255,0.4);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  display: inline-block;
}
.spinner-red {
  width: 15px; height: 15px;
  border: 2px solid rgba(255,255,255,0.4);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  display: inline-block;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
