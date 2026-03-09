<template>
  <div class="auth-page">
    <div class="auth-card">
      <!-- Logo / Brand -->
      <div class="brand">
        <span class="brand-icon">🔐</span>
        <h1 class="brand-name">Cocow SSO</h1>
        <p class="brand-sub">
          <template v-if="oidc.hasPending">
            Create an account to authorize <strong>{{ oidc.params.clientId }}</strong>
          </template>
          <template v-else>Create your account</template>
        </p>
      </div>

      <!-- Error banner -->
      <div v-if="store.error" class="alert alert-error">
        {{ store.error }}
      </div>

      <form @submit.prevent="handleRegister" novalidate>
        <div class="form-group">
          <label for="username">Username</label>
          <input
            id="username"
            v-model.trim="form.username"
            type="text"
            placeholder="Choose a username"
            autocomplete="username"
            :class="{ error: v.username }"
            @input="v.username = ''"
          />
          <span v-if="v.username" class="field-error">{{ v.username }}</span>
        </div>

        <div class="form-group">
          <label for="email">Email</label>
          <input
            id="email"
            v-model.trim="form.email"
            type="email"
            placeholder="you@example.com"
            autocomplete="email"
            :class="{ error: v.email }"
            @input="v.email = ''"
          />
          <span v-if="v.email" class="field-error">{{ v.email }}</span>
        </div>

        <div class="form-group">
          <label for="password">Password</label>
          <div class="input-wrapper">
            <input
              id="password"
              v-model="form.password"
              :type="showPassword ? 'text' : 'password'"
              placeholder="Create a strong password"
              autocomplete="new-password"
              :class="{ error: v.password }"
              @input="v.password = ''"
            />
            <button type="button" class="toggle-pw" @click="showPassword = !showPassword" tabindex="-1">
              {{ showPassword ? '🙈' : '👁️' }}
            </button>
          </div>
          <span v-if="v.password" class="field-error">{{ v.password }}</span>

          <!-- Password strength meter -->
          <div v-if="form.password" class="strength-bar">
            <div class="strength-fill" :class="strengthClass" :style="{ width: strengthPct + '%' }"></div>
          </div>
          <span v-if="form.password" class="strength-label" :class="strengthClass">{{ strengthLabel }}</span>
        </div>

        <div class="form-group">
          <label for="confirmPassword">Confirm Password</label>
          <div class="input-wrapper">
            <input
              id="confirmPassword"
              v-model="form.confirmPassword"
              :type="showConfirm ? 'text' : 'password'"
              placeholder="Repeat your password"
              autocomplete="new-password"
              :class="{ error: v.confirmPassword }"
              @input="v.confirmPassword = ''"
            />
            <button type="button" class="toggle-pw" @click="showConfirm = !showConfirm" tabindex="-1">
              {{ showConfirm ? '🙈' : '👁️' }}
            </button>
          </div>
          <span v-if="v.confirmPassword" class="field-error">{{ v.confirmPassword }}</span>
        </div>

        <label class="checkbox-label">
          <input type="checkbox" v-model="form.rememberMe" />
          <span>Remember me for 30 days</span>
        </label>

        <button type="submit" class="btn btn-primary" :disabled="store.loading">
          <span v-if="store.loading" class="spinner"></span>
          <span>{{ store.loading ? 'Creating account…' : 'Create Account' }}</span>
        </button>
      </form>

      <p class="switch-link">
        Already have an account?
        <router-link to="/login">Sign in</router-link>
      </p>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth.js'
import { useOidcStore } from '../stores/oidc.js'

const store = useAuthStore()
const oidc  = useOidcStore()
const router = useRouter()

onMounted(() => store.clearError())

const form = reactive({ username: '', email: '', password: '', confirmPassword: '', rememberMe: false })
const showPassword = ref(false)
const showConfirm = ref(false)
const v = reactive({ username: '', email: '', password: '', confirmPassword: '' })

// ── Password strength ──────────────────────────────────────────────────────
const strengthScore = computed(() => {
  const p = form.password
  if (!p) return 0
  let s = 0
  if (p.length >= 8) s++
  if (p.length >= 12) s++
  if (/[A-Z]/.test(p)) s++
  if (/[0-9]/.test(p)) s++
  if (/[^A-Za-z0-9]/.test(p)) s++
  return s
})

const strengthPct = computed(() => (strengthScore.value / 5) * 100)
const strengthClass = computed(() => ['', 'weak', 'weak', 'fair', 'good', 'strong'][strengthScore.value])
const strengthLabel = computed(() => ['', 'Weak', 'Weak', 'Fair', 'Good', 'Strong'][strengthScore.value])

// ── Validation ─────────────────────────────────────────────────────────────
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function validate() {
  let ok = true
  if (!form.username || form.username.length < 3) {
    v.username = 'Username must be at least 3 characters'; ok = false
  }
  if (!form.email || !EMAIL_RE.test(form.email)) {
    v.email = 'Please enter a valid email address'; ok = false
  }
  if (!form.password || form.password.length < 8) {
    v.password = 'Password must be at least 8 characters'; ok = false
  }
  if (form.password !== form.confirmPassword) {
    v.confirmPassword = 'Passwords do not match'; ok = false
  }
  return ok
}

async function handleRegister() {
  if (!validate()) return
  const ok = await store.register(form.username, form.email, form.password, form.rememberMe)
  if (ok) {
    // If an OAuth2 / OIDC flow is in progress, go to the consent screen
    router.push(oidc.hasPending ? { name: 'Authorize' } : { name: 'Dashboard' })
  }
}
</script>

<style scoped>
@import '../assets/auth.css';

.strength-bar {
  height: 4px;
  background: var(--border);
  border-radius: 2px;
  margin-top: 6px;
  overflow: hidden;
}
.strength-fill {
  height: 100%;
  border-radius: 2px;
  transition: width 0.3s ease, background 0.3s ease;
}
.strength-fill.weak   { background: #ef4444; }
.strength-fill.fair   { background: #f59e0b; }
.strength-fill.good   { background: #3b82f6; }
.strength-fill.strong { background: #22c55e; }

.strength-label {
  font-size: 0.75rem;
  margin-top: 2px;
}
.strength-label.weak   { color: #ef4444; }
.strength-label.fair   { color: #f59e0b; }
.strength-label.good   { color: #3b82f6; }
.strength-label.strong { color: #22c55e; }
</style>
