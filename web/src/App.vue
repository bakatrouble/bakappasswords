<script setup lang="ts">
import { computed, h, onMounted, reactive, ref, resolveComponent } from 'vue'

type Kind = 'basic' | 'bearer'
interface Credential {
  id: number
  kind: Kind
  label: string
  username: string | null
  created_at: string
}
interface Created extends Credential {
  token?: string
}

const TOKEN_KEY = 'admin_jwt'
const API = `${import.meta.env.BASE_URL}api`

const token = ref<string | null>(sessionStorage.getItem(TOKEN_KEY))
const password = ref('')
const loginError = ref('')
const loginBusy = ref(false)

const creds = ref<Credential[]>([])
const error = ref('')
const createOpen = ref(false)
const tokenOpen = ref(false)
const createBusy = ref(false)
const newToken = ref('')

const form = reactive({ kind: 'bearer' as Kind, label: '', username: '', password: '' })
const kindItems = [
  { label: 'Bearer token', value: 'bearer' },
  { label: 'Basic (username and password)', value: 'basic' },
]

const UButton = resolveComponent('UButton')

const columns = [
  { accessorKey: 'label', header: 'Label' },
  { accessorKey: 'kind', header: 'Type' },
  { id: 'username', header: 'Username', cell: ({ row }: any) => row.original.username ?? '—' },
  { accessorKey: 'created_at', header: 'Created (UTC)' },
  {
    id: 'actions',
    header: '',
    cell: ({ row }: any) =>
      h(
        UButton,
        {
          color: 'error',
          variant: 'ghost',
          size: 'sm',
          icon: 'i-lucide-trash-2',
          onClick: () => remove(row.original as Credential),
        },
        () => 'Delete',
      ),
  },
]

const loggedIn = computed(() => token.value !== null)

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body) headers.set('Content-Type', 'application/json')
  if (token.value) headers.set('Authorization', `Bearer ${token.value}`)
  const res = await fetch(`${API}${path}`, { ...init, headers })
  if (res.status === 401 && path !== '/login') {
    logout()
    throw new Error('Session expired, sign in again')
  }
  if (!res.ok) throw new Error((await res.text()) || res.statusText)
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T)
}

async function login() {
  loginBusy.value = true
  loginError.value = ''
  try {
    const r = await api<{ token: string }>('/login', {
      method: 'POST',
      body: JSON.stringify({ password: password.value }),
    })
    token.value = r.token
    sessionStorage.setItem(TOKEN_KEY, r.token)
    password.value = ''
    await load()
  } catch {
    loginError.value = 'Invalid password'
  } finally {
    loginBusy.value = false
  }
}

function logout() {
  token.value = null
  sessionStorage.removeItem(TOKEN_KEY)
  creds.value = []
}

async function load() {
  error.value = ''
  try {
    creds.value = await api<Credential[]>('/credentials')
  } catch (e) {
    error.value = (e as Error).message
  }
}

function resetForm() {
  form.kind = 'bearer'
  form.label = ''
  form.username = ''
  form.password = ''
}

async function create() {
  createBusy.value = true
  error.value = ''
  try {
    const body =
      form.kind === 'basic'
        ? { kind: 'basic', label: form.label, username: form.username, password: form.password }
        : { kind: 'bearer', label: form.label }
    const created = await api<Created>('/credentials', {
      method: 'POST',
      body: JSON.stringify(body),
    })
    createOpen.value = false
    resetForm()
    if (created.token) {
      newToken.value = created.token
      tokenOpen.value = true
    }
    await load()
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    createBusy.value = false
  }
}

async function remove(c: Credential) {
  if (!window.confirm(`Delete credential "${c.label}"?`)) return
  try {
    await api<void>(`/credentials/${c.id}`, { method: 'DELETE' })
    await load()
  } catch (e) {
    error.value = (e as Error).message
  }
}

async function copyToken() {
  await navigator.clipboard.writeText(newToken.value)
}

onMounted(() => {
  if (loggedIn.value) load()
})
</script>

<template>
  <UApp>
    <main class="min-h-screen bg-neutral-950 text-neutral-100 p-6">
      <!-- Sign in -->
      <div v-if="!loggedIn" class="max-w-sm mx-auto mt-24">
        <UCard class="bg-neutral-900 ring-neutral-800">
          <template #header>
            <h1 class="text-lg font-semibold">Admin sign in</h1>
          </template>
          <form class="flex flex-col gap-4" @submit.prevent="login">
            <UFormField label="Password">
              <UInput v-model="password" type="password" autocomplete="current-password" class="w-full" />
            </UFormField>
            <UAlert v-if="loginError" color="error" variant="subtle" :title="loginError" />
            <UButton type="submit" block :loading="loginBusy" :disabled="!password">Sign in</UButton>
          </form>
        </UCard>
      </div>

      <!-- Credentials -->
      <div v-else class="max-w-5xl mx-auto flex flex-col gap-6">
        <header class="flex items-center justify-between">
          <h1 class="text-xl font-semibold">Credentials</h1>
          <div class="flex gap-2">
            <UButton icon="i-lucide-plus" @click="createOpen = true">New credential</UButton>
            <UButton color="neutral" variant="outline" icon="i-lucide-log-out" @click="logout">Sign out</UButton>
          </div>
        </header>

        <UAlert v-if="error" color="error" variant="subtle" :title="error" />

        <UCard class="bg-neutral-900 ring-neutral-800">
          <UTable :data="creds" :columns="columns" />
          <p v-if="!creds.length" class="text-sm text-neutral-400 py-6 text-center">No credentials yet.</p>
        </UCard>
      </div>

      <!-- New credential -->
      <UModal v-model:open="createOpen" title="New credential">
        <template #body>
          <form class="flex flex-col gap-4" @submit.prevent="create">
            <UFormField label="Type">
              <USelect v-model="form.kind" :items="kindItems" class="w-full" />
            </UFormField>
            <UFormField label="Label">
              <UInput v-model="form.label" required class="w-full" />
            </UFormField>
            <template v-if="form.kind === 'basic'">
              <UFormField label="Username">
                <UInput v-model="form.username" required class="w-full" />
              </UFormField>
              <UFormField label="Password">
                <UInput v-model="form.password" type="password" required class="w-full" />
              </UFormField>
            </template>
            <UButton type="submit" block :loading="createBusy">Create</UButton>
          </form>
        </template>
      </UModal>

      <!-- Bearer token, shown once -->
      <UModal v-model:open="tokenOpen" title="Bearer token">
        <template #body>
          <div class="flex flex-col gap-4">
            <UAlert color="warning" variant="subtle" title="Shown once. Copy it now." />
            <code class="block break-all rounded bg-neutral-800 p-3 text-sm">{{ newToken }}</code>
            <UButton icon="i-lucide-copy" block @click="copyToken">Copy</UButton>
          </div>
        </template>
      </UModal>
    </main>
  </UApp>
</template>
