import { createRouter, createWebHistory } from "vue-router";
import { useAuthStore } from "../stores/auth.js";
import { useOidcStore } from "../stores/oidc.js";

const routes = [
  {
    path: "/",
    redirect: "/dashboard",
  },
  {
    path: "/login",
    name: "Login",
    component: () => import("../views/LoginView.vue"),
    meta: { guestOnly: true },
  },
  {
    path: "/register",
    name: "Register",
    component: () => import("../views/RegisterView.vue"),
    meta: { guestOnly: true },
  },
  {
    path: "/dashboard",
    name: "Dashboard",
    component: () => import("../views/DashboardView.vue"),
    meta: { requiresAuth: true },
  },
  {
    // OAuth2 / OIDC authorization endpoint — receives the client redirect
    path: "/oauth/authorize",
    name: "Authorize",
    component: () => import("../views/AuthorizeView.vue"),
    // No meta flags — the guard below handles auth logic explicitly
  },
  {
    path: "/:pathMatch(.*)*",
    redirect: "/",
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

// Navigation guards
router.beforeEach(async (to) => {
  const auth = useAuthStore();
  const oidc = useOidcStore();

  // ── Capture OIDC params when the client app redirects here ──────────────
  // e.g. /oauth/authorize?response_type=code&client_id=...&redirect_uri=...
  if (to.name === "Authorize" && to.query.client_id) {
    oidc.capture(to.query);
  }

  // Try to restore an existing server-side session ─────────────────────────
  if (auth.user === null && !auth.loading) {
    await auth.fetchUser();
  }

  // ── /oauth/authorize guard ───────────────────────────────────────────────
  if (to.name === "Authorize") {
    // Must be logged in to see the consent screen
    if (!auth.isAuthenticated()) {
      return { name: "Login" };
    }
    // Require valid OIDC params (either from query or sessionStorage)
    if (!oidc.hasPending) {
      return { name: "Dashboard" };
    }
    return; // proceed to AuthorizeView
  }

  // ── Standard guards ──────────────────────────────────────────────────────
  if (to.meta.requiresAuth && !auth.isAuthenticated()) {
    return { name: "Login" };
  }

  if (to.meta.guestOnly && auth.isAuthenticated()) {
    // If there are pending OIDC params, go to the consent screen
    if (oidc.hasPending) {
      return { name: "Authorize" };
    }
    return { name: "Dashboard" };
  }
});

export default router;
