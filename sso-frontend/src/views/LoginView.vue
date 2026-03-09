<template>
  <div class="auth-page">
    <div class="auth-card">
      <!-- Logo / Brand -->
      <div class="brand">
        <span class="brand-icon">🔐</span>
        <h1 class="brand-name">Cocow SSO</h1>
        <p class="brand-sub">
          <template v-if="oidc.hasPending">
            Sign in to authorize <strong>{{ oidc.params.clientId }}</strong>
          </template>
          <template v-else>Sign in to your account</template>
        </p>
      </div>

      <!-- Error banner -->
      <div v-if="store.error" class="alert alert-error">
        {{ store.error }}
      </div>

      <form @submit.prevent="handleLogin" novalidate>
        <div class="form-group">
          <label for="username">Username</label>
          <input
            id="username"
            v-model.trim="form.username"
            type="text"
            placeholder="Enter your username"
            autocomplete="username"
            :class="{ error: v.username }"
            @input="v.username = ''"
          />
          <span v-if="v.username" class="field-error">{{ v.username }}</span>
        </div>

        <div class="form-group">
          <label for="password">Password</label>
          <div class="input-wrapper">
            <input
              id="password"
              v-model="form.password"
              :type="showPassword ? 'text' : 'password'"
              placeholder="Enter your password"
              autocomplete="current-password"
              :class="{ error: v.password }"
              @input="v.password = ''"
            />
            <button type="button" class="toggle-pw" @click="showPassword = !showPassword" tabindex="-1">
              {{ showPassword ? '🙈' : '👁️' }}
            </button>
          </div>
          <span v-if="v.password" class="field-error">{{ v.password }}</span>
        </div>

        <label class="checkbox-label">
          <input type="checkbox" v-model="form.rememberMe" />
          <span>Remember me for 30 days</span>
        </label>

        <button type="submit" class="btn btn-primary" :disabled="store.loading">
          <span v-if="store.loading" class="spinner"></span>
          <span>{{ store.loading ? 'Signing in…' : 'Sign In' }}</span>
        </button>
      </form>

      <p class="switch-link">
        Don't have an account?
        <router-link to="/register">Create one</router-link>
      </p>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth.js'
import { useOidcStore } from '../stores/oidc.js'

const store = useAuthStore()
const oidc  = useOidcStore()
const router = useRouter()

onMounted(() => store.clearError())

const form = reactive({ username: '', password: '', rememberMe: false })
const showPassword = ref(false)
const v = reactive({ username: '', password: '' })

function validate() {
  let ok = true
  if (!form.username) { v.username = 'Username is required'; ok = false }
  if (!form.password) { v.password = 'Password is required'; ok = false }
  return ok
}

async function handleLogin() {
  if (!validate()) return
  const ok = await store.login(form.username, form.password, form.rememberMe)
  if (ok) {
    // If an OAuth2 / OIDC flow is in progress, go to the consent screen
    router.push(oidc.hasPending ? { name: 'Authorize' } : { name: 'Dashboard' })
  }
}
</script>

<style scoped>
@import '../assets/auth.css';
</style>
