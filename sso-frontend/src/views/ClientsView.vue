<template>
  <AppShell>
    <div class="page-header">
      <h2 class="page-title">OAuth2 Clients</h2>
      <button class="btn btn-primary" @click="openCreate">+ New Client</button>
    </div>

    <!-- Error banner -->
    <div v-if="store.error" class="alert alert-error">{{ store.error }}</div>

    <!-- Loading -->
    <div v-if="store.loading && !store.clients.length" class="state-empty">
      <div class="spinner-lg"></div>
      <p>Loading clients…</p>
    </div>

    <!-- Empty state -->
    <div v-else-if="!store.clients.length" class="state-empty">
      <p>No clients registered yet.</p>
      <button class="btn btn-primary" @click="openCreate">Register your first client</button>
    </div>

    <!-- Client list -->
    <template v-else>
      <div v-for="client in store.clients" :key="client.id" class="client-card">
        <div class="client-top">
          <div class="client-info">
            <span class="client-name">{{ client.client_name }}</span>
            <span class="client-type-chip">{{ client.client_type }}</span>
            <span class="badge" :class="client.enabled ? 'badge-green' : 'badge-red'">
              {{ client.enabled ? 'Enabled' : 'Disabled' }}
            </span>
          </div>
          <div class="client-actions">
            <button class="btn-icon" title="Edit" @click="openEdit(client)">✏️</button>
            <button
              class="btn-icon"
              :title="client.enabled ? 'Disable' : 'Enable'"
              @click="toggleEnabled(client)"
            >{{ client.enabled ? '⏸️' : '▶️' }}</button>
            <button class="btn-icon" title="Regenerate Secret" @click="doRegenerateSecret(client)">🔑</button>
            <button class="btn-icon btn-icon-danger" title="Delete" @click="confirmDelete(client)">🗑️</button>
          </div>
        </div>

        <div class="client-meta">
          <div class="meta-row">
            <span class="meta-label">Client ID</span>
            <code class="meta-val">{{ client.client_id }}</code>
          </div>
          <div v-if="client.client_secret" class="meta-row">
            <span class="meta-label">Client Secret</span>
            <code class="meta-val secret">{{ client.client_secret }}</code>
            <span class="secret-warn">⚠ Copy now — won't be shown again</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">Redirect URIs</span>
            <span class="meta-val">{{ (client.redirect_uris ?? []).join(', ') }}</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">Scopes</span>
            <span class="meta-val">{{ (client.scopes ?? []).join(', ') }}</span>
          </div>
        </div>
      </div>
    </template>

    <!-- ── Create / Edit Modal ──────────────────────────────────────────────── -->
    <div v-if="modal.open" class="modal-backdrop" @click.self="modal.open = false">
      <div class="modal-card">
        <h3 class="modal-title">{{ modal.isEdit ? 'Edit Client' : 'Register New Client' }}</h3>

        <div v-if="modal.error" class="alert alert-error">{{ modal.error }}</div>

        <form @submit.prevent="handleSubmit" novalidate>
          <div class="form-group">
            <label>Client Name</label>
            <input v-model.trim="modal.form.clientName" type="text" placeholder="My App" required />
          </div>

          <div v-if="!modal.isEdit" class="form-group">
            <label>Client Type</label>
            <select v-model="modal.form.clientType">
              <option value="CONFIDENTIAL">Confidential (server-side)</option>
              <option value="PUBLIC">Public (SPA / mobile)</option>
            </select>
          </div>

          <div class="form-group">
            <label>Redirect URIs <small>(one per line)</small></label>
            <textarea v-model="modal.redirectUrisText" rows="3" placeholder="https://myapp.example.com/callback" />
          </div>

          <div class="form-group">
            <label>Scopes</label>
            <div class="scope-checkboxes">
              <label
                v-for="s in store.allowedScopes"
                :key="s"
                class="scope-checkbox-label"
              >
                <input type="checkbox" :value="s" v-model="modal.form.scopes" />
                <span>{{ s }}</span>
                <span v-if="store.scopeDescriptions[s]" class="scope-hint">— {{ store.scopeDescriptions[s] }}</span>
              </label>
            </div>
          </div>

          <div class="modal-actions">
            <button type="button" class="btn btn-ghost" @click="modal.open = false">Cancel</button>
            <button type="submit" class="btn btn-primary" :disabled="store.loading">
              <span v-if="store.loading" class="spinner"></span>
              {{ modal.isEdit ? 'Save Changes' : 'Register' }}
            </button>
          </div>
        </form>
      </div>
    </div>

    <!-- ── Delete Confirm Modal ─────────────────────────────────────────────── -->
    <div v-if="deleteTarget" class="modal-backdrop" @click.self="deleteTarget = null">
      <div class="modal-card modal-sm">
        <h3 class="modal-title">Delete Client</h3>
        <p class="modal-body">
          Are you sure you want to permanently delete
          <strong>{{ deleteTarget.client_name }}</strong>?
          All associated tokens will be revoked.
        </p>
        <div v-if="deleteError" class="alert alert-error">{{ deleteError }}</div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="deleteTarget = null">Cancel</button>
          <button class="btn btn-danger" :disabled="store.loading" @click="doDelete">
            <span v-if="store.loading" class="spinner"></span>
            Delete
          </button>
        </div>
      </div>
    </div>
  </AppShell>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useClientStore } from '../stores/client.js'
import AppShell from '../components/AppShell.vue'

const store = useClientStore()

onMounted(async () => {
  store.clearError()
  await Promise.all([store.fetchAll(), store.fetchAllowedScopes()])
})

// ── Modal state ───────────────────────────────────────────────────────────
const modal = reactive({
  open: false,
  isEdit: false,
  editId: null,
  error: '',
  redirectUrisText: '',
  form: {
    clientName: '',
    clientType: 'CONFIDENTIAL',
    scopes: ['openid'],
  },
})

function openCreate() {
  modal.isEdit = false
  modal.editId = null
  modal.error = ''
  modal.redirectUrisText = ''
  modal.form.clientName = ''
  modal.form.clientType = 'CONFIDENTIAL'
  modal.form.scopes = ['openid']
  modal.open = true
}

function openEdit(client) {
  modal.isEdit = true
  modal.editId = client.id
  modal.error = ''
  modal.redirectUrisText = (client.redirect_uris ?? []).join('\n')
  modal.form.clientName = client.client_name
  modal.form.clientType = client.client_type
  modal.form.scopes = [...(client.scopes ?? [])]
  modal.open = true
}

async function handleSubmit() {
  modal.error = ''
  if (!modal.form.clientName.trim()) { modal.error = 'Client name is required'; return }

  const redirectUris = modal.redirectUrisText
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)

  if (!redirectUris.length) { modal.error = 'At least one redirect URI is required'; return }
  if (!modal.form.scopes.length) { modal.error = 'At least one scope is required'; return }

  let result
  if (modal.isEdit) {
    result = await store.update(modal.editId, {
      clientName: modal.form.clientName,
      redirectUris,
      scopes: modal.form.scopes,
    })
  } else {
    result = await store.create({
      clientName: modal.form.clientName,
      clientType: modal.form.clientType,
      redirectUris,
      scopes: modal.form.scopes,
    })
  }

  if (result.success) {
    modal.open = false
  } else {
    modal.error = store.error
  }
}

// ── Toggle / regenerate ───────────────────────────────────────────────────
async function toggleEnabled(client) {
  await store.setEnabled(client.id, !client.enabled)
}

async function doRegenerateSecret(client) {
  if (!confirm(`Regenerate the secret for "${client.client_name}"? The old secret will stop working immediately.`)) return
  await store.regenerateSecret(client.id)
}

// ── Delete ────────────────────────────────────────────────────────────────
const deleteTarget = ref(null)
const deleteError  = ref('')

function confirmDelete(client) {
  deleteTarget.value = client
  deleteError.value  = ''
}

async function doDelete() {
  const result = await store.remove(deleteTarget.value.id)
  if (result.success) {
    deleteTarget.value = null
  } else {
    deleteError.value = store.error
  }
}
</script>

<style scoped>
/* ── Page header ────────────────────────────────────────────────────────── */
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.page-title { margin: 0; font-size: 1.35rem; font-weight: 700; color: var(--text); }

/* ── Alert ──────────────────────────────────────────────────────────────── */
.alert {
  border-radius: calc(var(--radius) - 2px);
  padding: 0.7rem 1rem;
  font-size: 0.875rem;
}
.alert-error { background: #fee2e2; border: 1px solid #fca5a5; color: #b91c1c; }

/* ── Empty / loading state ──────────────────────────────────────────────── */
.state-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
  padding: 3rem 1rem;
  color: var(--text-muted);
  font-size: 0.9rem;
}
.spinner-lg {
  width: 32px; height: 32px;
  border: 3px solid var(--border);
  border-top-color: var(--primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

/* ── Client card ────────────────────────────────────────────────────────── */
.client-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}

.client-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}
.client-info {
  display: flex;
  align-items: center;
  gap: 0.55rem;
  flex-wrap: wrap;
}
.client-name {
  font-weight: 600;
  color: var(--text);
  font-size: 0.97rem;
}
.client-type-chip {
  font-size: 0.72rem;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.15rem 0.55rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.badge {
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
}
.badge-green { background: #dcfce7; color: #15803d; }
.badge-red   { background: #fee2e2; color: #991b1b; }

.client-actions { display: flex; gap: 0.25rem; }
.btn-icon {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.3rem 0.4rem;
  border-radius: 6px;
  font-size: 1rem;
  transition: background 0.15s;
}
.btn-icon:hover { background: var(--bg); }
.btn-icon-danger:hover { background: #fee2e2; }

/* ── Meta rows ──────────────────────────────────────────────────────────── */
.client-meta { display: flex; flex-direction: column; gap: 0.45rem; }
.meta-row {
  display: flex;
  align-items: baseline;
  gap: 0.6rem;
  font-size: 0.85rem;
  flex-wrap: wrap;
}
.meta-label {
  color: var(--text-muted);
  font-weight: 500;
  white-space: nowrap;
  min-width: 110px;
}
.meta-val { color: var(--text); word-break: break-all; }
.meta-val.secret { color: #dc2626; font-weight: 600; }
.secret-warn { font-size: 0.75rem; color: #d97706; }

code {
  font-family: ui-monospace, 'Cascadia Code', monospace;
  font-size: 0.82em;
}

/* ── Modal ──────────────────────────────────────────────────────────────── */
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.35);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: 1rem;
}
.modal-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.75rem;
  width: 100%;
  max-width: 520px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 8px 40px rgba(0,0,0,0.15);
}
.modal-sm { max-width: 380px; }
.modal-title { margin: 0 0 1.25rem; font-size: 1.05rem; font-weight: 700; color: var(--text); }
.modal-body { font-size: 0.9rem; color: var(--text-muted); line-height: 1.6; margin: 0 0 1rem; }

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.6rem;
  margin-top: 1.25rem;
}

/* ── Form ───────────────────────────────────────────────────────────────── */
form { display: flex; flex-direction: column; gap: 1rem; }
.form-group { display: flex; flex-direction: column; gap: 0.35rem; }
label { font-size: 0.875rem; font-weight: 500; color: var(--text); }

input[type='text'], select, textarea {
  width: 100%;
  padding: 0.6rem 0.9rem;
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) - 2px);
  background: var(--bg);
  color: var(--text);
  font-size: 0.92rem;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  box-sizing: border-box;
  font-family: inherit;
}
input:focus, select:focus, textarea:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(99,102,241,0.15);
}
textarea { resize: vertical; }

.scope-checkboxes { display: flex; flex-direction: column; gap: 0.4rem; }
.scope-checkbox-label {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.875rem;
  cursor: pointer;
  color: var(--text);
}
.scope-checkbox-label input { width: auto; }
.scope-hint { color: var(--text-muted); font-size: 0.8rem; }

/* ── Buttons ────────────────────────────────────────────────────────────── */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.45rem;
  padding: 0.6rem 1.1rem;
  border: none;
  border-radius: calc(var(--radius) - 2px);
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.2s, opacity 0.2s;
}
.btn:disabled { opacity: 0.6; cursor: not-allowed; }
.btn-primary { background: var(--primary); color: #fff; }
.btn-primary:hover:not(:disabled) { background: var(--primary-hover); }
.btn-danger { background: #dc2626; color: #fff; }
.btn-danger:hover:not(:disabled) { background: #b91c1c; }
.btn-ghost {
  background: var(--bg);
  color: var(--text-muted);
  border: 1px solid var(--border);
}
.btn-ghost:hover:not(:disabled) { color: var(--text); }

/* ── Spinner ────────────────────────────────────────────────────────────── */
.spinner {
  width: 14px; height: 14px;
  border: 2px solid rgba(255,255,255,0.4);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  display: inline-block;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
