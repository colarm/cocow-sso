<template>
  <AppShell>
    <div class="page-header">
      <h2 class="page-title">User Management</h2>
    </div>

    <!-- Error banner -->
    <div v-if="store.error" class="alert alert-error">{{ store.error }}</div>

    <!-- Loading -->
    <div v-if="store.loading && !store.users.length" class="state-empty">
      <div class="spinner-lg"></div>
      <p>Loading users…</p>
    </div>

    <!-- Empty -->
    <div v-else-if="!store.users.length" class="state-empty">
      <p>No users found.</p>
    </div>

    <!-- Table -->
    <template v-else>
      <div class="table-wrap">
        <table class="user-table">
          <colgroup>
            <col style="width: 4rem" />
            <col style="width: 14%" />
            <col style="width: 22%" />
            <col style="width: 16%" />
            <col style="width: 16%" />
            <col style="width: 10%" />
            <col style="width: 18%" />
          </colgroup>
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in store.users" :key="user.id">
              <td class="col-id">{{ user.id }}</td>
              <td class="col-name">{{ user.username }}</td>
              <td class="col-email">{{ user.email }}</td>
              <td>
                <select
                  class="role-select"
                  :value="user.role"
                  :disabled="user.id === authStore.user?.id || store.loading"
                  @change="onRoleChange(user, $event.target.value)"
                >
                  <option value="USER">USER</option>
                  <option value="CLIENT_ADMIN">CLIENT_ADMIN</option>
                  <option value="ADMIN">ADMIN</option>
                </select>
              </td>
              <td>
                <span class="badge" :class="user.enabled ? 'badge-green' : 'badge-red'">
                  {{ user.enabled ? 'Enabled' : 'Disabled' }}
                </span>
                <span v-if="user.locked" class="badge badge-orange">Locked</span>
              </td>
              <td class="col-date">{{ formatDate(user.created_at) }}</td>
              <td class="col-actions">
                <button
                  class="btn-icon"
                  :title="user.enabled ? 'Disable' : 'Enable'"
                  :disabled="user.id === authStore.user?.id || store.loading"
                  @click="toggleEnabled(user)"
                >{{ user.enabled ? '⏸️' : '▶️' }}</button>
                <button
                  class="btn-icon"
                  :title="user.locked ? 'Unlock' : 'Lock'"
                  :disabled="user.id === authStore.user?.id || store.loading"
                  @click="toggleLocked(user)"
                >{{ user.locked ? '🔓' : '🔒' }}</button>
                <button
                  class="btn-icon"
                  title="Reset Password"
                  :disabled="store.loading"
                  @click="openResetPassword(user)"
                >🔑</button>
                <button
                  class="btn-icon btn-icon-danger"
                  title="Delete"
                  :disabled="user.id === authStore.user?.id || store.loading"
                  @click="confirmDelete(user)"
                >🗑️</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div class="pagination">
        <button class="btn btn-ghost btn-sm" :disabled="store.page <= 0" @click="goPage(store.page - 1)">← Prev</button>
        <span class="page-info">Page {{ store.page + 1 }} / {{ store.totalPages }} &nbsp;({{ store.total }} users)</span>
        <button class="btn btn-ghost btn-sm" :disabled="store.page >= store.totalPages - 1" @click="goPage(store.page + 1)">Next →</button>
      </div>
    </template>

    <!-- ── Reset Password Modal ─────────────────────────────────────────────── -->
    <div v-if="resetTarget" class="modal-backdrop" @click.self="resetTarget = null">
      <div class="modal-card modal-sm">
        <h3 class="modal-title">Reset Password</h3>
        <p class="modal-body">Set a new password for <strong>{{ resetTarget.username }}</strong>.</p>
        <div v-if="modalError" class="alert alert-error">{{ modalError }}</div>
        <div class="form-group">
          <input
            v-model.trim="newPassword"
            type="password"
            placeholder="New password (min 8 chars)"
            autocomplete="new-password"
          />
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="resetTarget = null">Cancel</button>
          <button class="btn btn-primary" :disabled="store.loading" @click="doResetPassword">
            <span v-if="store.loading" class="spinner"></span>
            Reset
          </button>
        </div>
      </div>
    </div>

    <!-- ── Delete Confirm Modal ─────────────────────────────────────────────── -->
    <div v-if="deleteTarget" class="modal-backdrop" @click.self="deleteTarget = null">
      <div class="modal-card modal-sm">
        <h3 class="modal-title">Delete User</h3>
        <p class="modal-body">
          Permanently delete <strong>{{ deleteTarget.username }}</strong>?
          This cannot be undone.
        </p>
        <div v-if="modalError" class="alert alert-error">{{ modalError }}</div>
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
import { ref, onMounted } from 'vue'
import { useAdminStore } from '../stores/admin.js'
import { useAuthStore } from '../stores/auth.js'
import AppShell from '../components/AppShell.vue'

const store     = useAdminStore()
const authStore = useAuthStore()

onMounted(() => {
  store.clearError()
  store.fetchUsers(0)
})

function goPage(p) {
  store.fetchUsers(p)
}

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString()
}

// ── Role ──────────────────────────────────────────────────────────────────
async function onRoleChange(user, role) {
  await store.updateRole(user.id, role)
}

// ── Enable / Lock toggles ─────────────────────────────────────────────────
async function toggleEnabled(user) {
  await store.setEnabled(user.id, !user.enabled)
}

async function toggleLocked(user) {
  await store.setLocked(user.id, !user.locked)
}

// ── Reset password ────────────────────────────────────────────────────────
const resetTarget = ref(null)
const newPassword = ref('')
const modalError  = ref('')

function openResetPassword(user) {
  resetTarget.value = user
  newPassword.value = ''
  modalError.value  = ''
}

async function doResetPassword() {
  if (newPassword.value.length < 8) {
    modalError.value = 'Password must be at least 8 characters'
    return
  }
  const result = await store.resetPassword(resetTarget.value.id, newPassword.value)
  if (result.success) {
    resetTarget.value = null
  } else {
    modalError.value = store.error
  }
}

// ── Delete ────────────────────────────────────────────────────────────────
const deleteTarget = ref(null)

function confirmDelete(user) {
  deleteTarget.value = user
  modalError.value   = ''
}

async function doDelete() {
  const result = await store.deleteUser(deleteTarget.value.id)
  if (result.success) {
    deleteTarget.value = null
  } else {
    modalError.value = store.error
  }
}
</script>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.page-title { margin: 0; font-size: 1.35rem; font-weight: 700; color: var(--text); }

.alert { border-radius: calc(var(--radius) - 2px); padding: 0.7rem 1rem; font-size: 0.875rem; }
.alert-error { background: #fee2e2; border: 1px solid #fca5a5; color: #b91c1c; }

.state-empty {
  display: flex; flex-direction: column; align-items: center;
  gap: 1rem; padding: 3rem 1rem; color: var(--text-muted); font-size: 0.9rem;
}
.spinner-lg {
  width: 32px; height: 32px;
  border: 3px solid var(--border); border-top-color: var(--primary);
  border-radius: 50%; animation: spin 0.8s linear infinite;
}

/* Table */
.table-wrap { width: 100%; }
.user-table {
  width: 100%; border-collapse: collapse; font-size: 0.875rem; table-layout: fixed;
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
}
.user-table th, .user-table td {
  padding: 0.65rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.user-table th { font-weight: 600; color: var(--text-muted); background: var(--bg); }
.user-table tr:last-child td { border-bottom: none; }

.col-id    { width: 3rem; color: var(--text-muted); }
.col-date  { white-space: nowrap; color: var(--text-muted); font-size: 0.8rem; }
.col-actions { white-space: nowrap; }

.role-select {
  font-size: 0.8rem; padding: 0.2rem 0.4rem;
  border: 1px solid var(--border); border-radius: 4px;
  background: var(--bg); color: var(--text); cursor: pointer;
}
.role-select:disabled { opacity: 0.5; cursor: not-allowed; }

/* Badges */
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; margin-right: 0.25rem; }
.badge-green  { background: #dcfce7; color: #15803d; }
.badge-red    { background: #fee2e2; color: #b91c1c; }
.badge-orange { background: #fef3c7; color: #92400e; }

/* Action buttons */
.btn-icon {
  background: none; border: none; cursor: pointer; font-size: 1rem;
  padding: 0.2rem 0.35rem; border-radius: 4px; transition: background 0.15s;
}
.btn-icon:hover:not(:disabled) { background: var(--border); }
.btn-icon:disabled { opacity: 0.35; cursor: not-allowed; }
.btn-icon-danger:hover:not(:disabled) { background: #fee2e2; }

/* Pagination */
.pagination {
  display: flex; align-items: center; justify-content: center;
  gap: 1rem; padding: 1rem 0; font-size: 0.875rem; color: var(--text-muted);
}

/* Buttons */
.btn { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.5rem 1.1rem; border-radius: var(--radius); font-size: 0.875rem; font-weight: 500; border: none; cursor: pointer; transition: opacity 0.15s; }
.btn:disabled { opacity: 0.55; cursor: not-allowed; }
.btn-sm { padding: 0.35rem 0.8rem; font-size: 0.8rem; }
.btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text); }
.btn-ghost:hover:not(:disabled) { background: var(--border); }
.btn-primary { background: var(--primary); color: #fff; }
.btn-primary:hover:not(:disabled) { opacity: 0.88; }
.btn-danger { background: #dc2626; color: #fff; }
.btn-danger:hover:not(:disabled) { opacity: 0.88; }

/* Modal */
.modal-backdrop {
  position: fixed; inset: 0; background: rgba(0,0,0,0.45);
  display: flex; align-items: center; justify-content: center; z-index: 100;
}
.modal-card {
  background: var(--surface); border-radius: var(--radius);
  padding: 1.75rem; width: 100%; max-width: 420px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.18); display: flex; flex-direction: column; gap: 1rem;
}
.modal-sm { max-width: 360px; }
.modal-title { margin: 0; font-size: 1.1rem; font-weight: 700; }
.modal-body  { margin: 0; font-size: 0.9rem; color: var(--text-muted); }
.modal-actions { display: flex; justify-content: flex-end; gap: 0.6rem; }

.form-group { display: flex; flex-direction: column; gap: 0.35rem; }
.form-group input {
  padding: 0.55rem 0.75rem; border: 1px solid var(--border); border-radius: var(--radius);
  font-size: 0.9rem; background: var(--bg); color: var(--text);
}

.spinner {
  width: 14px; height: 14px;
  border: 2px solid rgba(255,255,255,0.4); border-top-color: #fff;
  border-radius: 50%; animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
