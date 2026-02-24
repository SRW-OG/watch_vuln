const el = (id) => document.getElementById(id)

const state = {
  user: null,
  offset: 0,
  limit: 20,
  total: 0,
  q: "",
  severity: "",
  selectedId: null,
  view: "vulns",
  config: {
    editable: false,
    format: "",
    meta: null,
    data: null,
    inputs: {},
    pusherItems: [],
  },
}

async function api(path, options) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...options,
  })
  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch (e) {
    data = null
  }
  if (!res.ok) {
    const msg = data && data.error ? data.error : `HTTP ${res.status}`
    const err = new Error(msg)
    err.status = res.status
    err.data = data
    throw err
  }
  return data
}

function show(elm, visible) {
  if (!elm) return
  elm.classList.toggle("hidden", !visible)
}

function setText(elm, text) {
  if (!elm) return
  elm.textContent = text || ""
}

function formatTime(s) {
  if (!s) return ""
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return s
  const pad = (n) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function qs(params) {
  const u = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "") return
    u.set(k, String(v))
  })
  const s = u.toString()
  return s ? `?${s}` : ""
}

async function bootstrap() {
  try {
    const me = await api("/api/me", { method: "GET" })
    state.user = me.username
    renderAuthed()
    showView("vulns")
  } catch (e) {
    renderUnauthed()
  }
}

function renderAuthed() {
  show(el("loginView"), false)
  show(el("appView"), true)
  show(el("logoutBtn"), true)
  show(el("navVulns"), true)
  show(el("navConfig"), true)
  setText(el("currentUser"), state.user ? `已登录：${state.user}` : "")
}

function renderUnauthed() {
  state.user = null
  show(el("appView"), false)
  show(el("logoutBtn"), false)
  show(el("navVulns"), false)
  show(el("navConfig"), false)
  setText(el("currentUser"), "")
  show(el("loginView"), true)
}

async function handleLogin(ev) {
  ev.preventDefault()
  show(el("loginError"), false)
  const username = el("loginUsername").value.trim()
  const password = el("loginPassword").value
  try {
    const res = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    })
    state.user = res.username
    renderAuthed()
    state.offset = 0
    state.selectedId = null
    showView("vulns")
  } catch (e) {
    setText(el("loginError"), e.message || "登录失败")
    show(el("loginError"), true)
  }
}

async function handleLogout() {
  try {
    await api("/api/logout", { method: "POST", body: JSON.stringify({}) })
  } catch (e) {
  } finally {
    renderUnauthed()
  }
}

async function showView(view) {
  state.view = view
  show(el("vulnView"), view === "vulns")
  show(el("configView"), view === "config")
  if (view === "vulns") {
    await loadList(true)
  }
  if (view === "config") {
    await loadConfig()
  }
}

async function loadList(resetDetail) {
  const params = {
    q: state.q,
    severity: state.severity,
    offset: state.offset,
    limit: state.limit,
  }
  const res = await api("/api/v1/vulns" + qs(params), { method: "GET" })
  state.total = res.total || 0
  renderList(res.items || [])
  renderMeta()
  if (resetDetail) renderDetail(null)
}

function renderMeta() {
  const start = state.total === 0 ? 0 : state.offset + 1
  const end = Math.min(state.offset + state.limit, state.total)
  setText(el("listMeta"), `共 ${state.total} 条，显示 ${start}-${end}`)
  el("prevBtn").disabled = state.offset <= 0
  el("nextBtn").disabled = state.offset + state.limit >= state.total
}

function renderList(items) {
  const tbody = el("vulnTbody")
  tbody.innerHTML = ""
  if (!items.length) {
    const tr = document.createElement("tr")
    const td = document.createElement("td")
    td.colSpan = 7
    td.className = "muted"
    td.textContent = "暂无数据"
    tr.appendChild(td)
    tbody.appendChild(tr)
    return
  }
  items.forEach((v) => {
    const tr = document.createElement("tr")

    const tdId = document.createElement("td")
    tdId.textContent = String(v.id)
    tr.appendChild(tdId)

    const tdKey = document.createElement("td")
    const btn = document.createElement("button")
    btn.className = "rowBtn"
    btn.textContent = v.key || ""
    btn.addEventListener("click", () => selectVuln(v.id))
    tdKey.appendChild(btn)
    tr.appendChild(tdKey)

    const tdTitle = document.createElement("td")
    tdTitle.textContent = v.title || ""
    tr.appendChild(tdTitle)

    const tdSev = document.createElement("td")
    tdSev.textContent = v.severity || ""
    tr.appendChild(tdSev)

    const tdCve = document.createElement("td")
    tdCve.textContent = v.cve || ""
    tr.appendChild(tdCve)

    const tdFrom = document.createElement("td")
    tdFrom.textContent = v.from || ""
    tr.appendChild(tdFrom)

    const tdTime = document.createElement("td")
    tdTime.textContent = formatTime(v.create_time)
    tr.appendChild(tdTime)

    tbody.appendChild(tr)
  })
}

async function selectVuln(id) {
  state.selectedId = id
  renderDetail("加载中…")
  try {
    const v = await api(`/api/v1/vulns/${id}`, { method: "GET" })
    renderDetail(v)
  } catch (e) {
    renderDetail("加载失败")
  }
}

function renderDetail(v) {
  if (!v) {
    setText(el("detailKey"), "")
    setText(el("detailBody"), "选择一条记录查看详情")
    el("detailBody").classList.add("muted")
    return
  }
  if (typeof v === "string") {
    setText(el("detailKey"), "")
    setText(el("detailBody"), v)
    el("detailBody").classList.add("muted")
    return
  }
  el("detailBody").classList.remove("muted")
  setText(el("detailKey"), v.key || "")
  const lines = []
  lines.push(`标题：${v.title || ""}`)
  lines.push(`严重度：${v.severity || ""}`)
  lines.push(`CVE：${v.cve || ""}`)
  lines.push(`来源：${v.from || ""}`)
  lines.push(`披露时间：${v.disclosure || ""}`)
  lines.push(`创建时间：${formatTime(v.create_time)}`)
  lines.push(`更新时间：${formatTime(v.update_time)}`)
  lines.push("")
  if (v.tags && v.tags.length) lines.push(`标签：${v.tags.join(", ")}`)
  if (v.references && v.references.length) lines.push(`参考：\n${v.references.join("\n")}`)
  if (v.github_search && v.github_search.length) lines.push(`GitHub 搜索：\n${v.github_search.join("\n")}`)
  if (v.solutions) lines.push(`解决方案：\n${v.solutions}`)
  if (v.description) lines.push(`描述：\n${v.description}`)
  setText(el("detailBody"), lines.join("\n"))
}

async function loadConfig() {
  setText(el("configStatus"), "")
  try {
    const res = await api("/api/v1/config", { method: "GET" })
    state.config.editable = !!res.editable
    state.config.format = res.format || ""
    state.config.meta = res.meta || null
    state.config.data = res.config || null
    renderConfigForm(state.config.meta, state.config.data, res.error || "")
    const file = res.file ? `（${res.file}）` : ""
    setText(el("configMeta"), state.config.editable ? `来源：${state.config.format}${file}` : (res.error || "不可编辑"))
    el("configSaveBtn").disabled = !state.config.editable
  } catch (e) {
    setText(el("configMeta"), "获取配置失败")
    el("configSaveBtn").disabled = true
  }
}

async function saveConfig() {
  setText(el("configStatus"), "")
  const cfg = collectConfigFromForm()
  try {
    const res = await api("/api/v1/config", {
      method: "PUT",
      body: JSON.stringify({ config: cfg }),
    })
    if (res && res.config) {
      state.config.data = res.config
      renderConfigForm(state.config.meta, state.config.data, "")
    }
    const parts = ["已保存"]
    if (res && res.apply && res.apply.applied) {
      parts.push("已生效")
      if (res.apply.requires_relogin) parts.push("需要重新登录")
      if (res.apply.requires_restart) parts.push("部分配置需重启生效")
    } else if (res && res.apply_error) {
      parts.push("未能全部生效：" + res.apply_error)
    } else {
      parts.push("未自动生效（可能需要重启）")
    }
    parts.push("敏感字段会以 ******** 显示")
    setText(el("configStatus"), parts.join("；"))
  } catch (e) {
    setText(el("configStatus"), e.message || "保存失败")
  }
}

function renderConfigForm(meta, cfg, errText) {
  const root = el("configForm")
  if (!root) return
  root.innerHTML = ""
  state.config.inputs = {}
  state.config.pusherItems = []

  if (errText) {
    setText(el("configMeta"), errText)
  }

  if (!meta || !cfg) {
    return
  }

  meta.sections = Array.isArray(meta.sections) ? meta.sections : []

  meta.sections.forEach((sec) => {
    const title = document.createElement("div")
    title.className = "configSectionTitle"
    title.textContent = sec.title || ""
    root.appendChild(title)

    const grid = document.createElement("div")
    grid.className = "configGrid"
    root.appendChild(grid)

    ;(sec.fields || []).forEach((f) => {
      const wrap = document.createElement("div")
      wrap.className = "field"

      const label = document.createElement("div")
      label.textContent = f.label || f.key
      wrap.appendChild(label)

      const input = buildFieldInput(f, cfg)
      wrap.appendChild(input)
      state.config.inputs[f.key] = input

      const help = document.createElement("div")
      help.className = "help"
      help.textContent = f.help || ""
      wrap.appendChild(help)

      grid.appendChild(wrap)
    })
  })

  const pusherTitle = document.createElement("div")
  pusherTitle.className = "configSectionTitle"
  pusherTitle.textContent = "推送"
  root.appendChild(pusherTitle)

  const pusherHelp = document.createElement("div")
  pusherHelp.className = "help"
  pusherHelp.textContent = "添加/编辑推送渠道。敏感字段留空或保留 ******** 会保留原值。"
  root.appendChild(pusherHelp)

  const list = document.createElement("div")
  list.className = "pusherList"
  root.appendChild(list)

  const types = (meta.pusher && meta.pusher.types) || []
  const typeMap = {}
  types.forEach((t) => {
    typeMap[t.type] = t
  })

  const pushers = Array.isArray(cfg.pusher) ? cfg.pusher : []
  pushers.forEach((p, idx) => addPusherItem(list, typeMap, p, idx))

  const actions = document.createElement("div")
  actions.className = "pusherActions"
  const addBtn = document.createElement("button")
  addBtn.className = "btn btn-secondary"
  addBtn.type = "button"
  addBtn.textContent = "添加推送"
  addBtn.addEventListener("click", () => addPusherItem(list, typeMap, { type: "dingding" }, -1))
  actions.appendChild(addBtn)
  root.appendChild(actions)
}

function buildFieldInput(meta, cfg) {
  const key = meta.key
  const t = meta.type || "text"
  if (t === "bool") {
    const input = document.createElement("input")
    input.type = "checkbox"
    input.className = "input"
    input.checked = !!cfg[key]
    return input
  }
  const input = document.createElement("input")
  input.className = "input"
  input.type = t === "password" ? "password" : "text"
  input.placeholder = meta.placeholder || ""
  const v = cfg[key]
  if (t === "tags") {
    input.value = Array.isArray(v) ? v.join(",") : ""
    return input
  }
  input.value = v === null || v === undefined ? "" : String(v)
  return input
}

function addPusherItem(list, typeMap, init, idx) {
  const item = document.createElement("div")
  item.className = "pusherItem"

  const row = document.createElement("div")
  row.className = "pusherRow"
  item.appendChild(row)

  const typeWrap = document.createElement("div")
  typeWrap.className = "field"
  const typeLabel = document.createElement("div")
  typeLabel.textContent = "类型"
  typeWrap.appendChild(typeLabel)
  const select = document.createElement("select")
  select.className = "input"
  Object.values(typeMap).forEach((t) => {
    const opt = document.createElement("option")
    opt.value = t.type
    opt.textContent = t.label || t.type
    select.appendChild(opt)
  })
  select.value = (init && init.type) || "dingding"
  typeWrap.appendChild(select)
  row.appendChild(typeWrap)

  const removeWrap = document.createElement("div")
  removeWrap.className = "field"
  const removeLabel = document.createElement("div")
  removeLabel.textContent = "操作"
  removeWrap.appendChild(removeLabel)
  const removeBtn = document.createElement("button")
  removeBtn.className = "btn btn-secondary"
  removeBtn.type = "button"
  removeBtn.textContent = "删除"
  removeBtn.addEventListener("click", () => {
    item.remove()
    state.config.pusherItems = state.config.pusherItems.filter((x) => x.el !== item)
  })
  removeWrap.appendChild(removeBtn)
  row.appendChild(removeWrap)

  const fieldsWrap = document.createElement("div")
  fieldsWrap.className = "configGrid"
  item.appendChild(fieldsWrap)

  const entry = { el: item, select, inputs: {} }
  state.config.pusherItems.push(entry)

  function renderFields() {
    fieldsWrap.innerHTML = ""
    entry.inputs = {}
    const t = typeMap[select.value]
    ;(t && t.fields ? t.fields : []).forEach((f) => {
      const wrap = document.createElement("div")
      wrap.className = "field"

      const label = document.createElement("div")
      label.textContent = f.label || f.key
      wrap.appendChild(label)

      const input = document.createElement("input")
      input.className = "input"
      input.type = f.type === "password" ? "password" : "text"
      input.placeholder = f.placeholder || ""
      const vv = init ? init[f.key] : ""
      input.value = vv === null || vv === undefined ? "" : String(vv)
      wrap.appendChild(input)

      const help = document.createElement("div")
      help.className = "help"
      help.textContent = f.help || ""
      wrap.appendChild(help)

      entry.inputs[f.key] = input
      fieldsWrap.appendChild(wrap)
    })
  }

  select.addEventListener("change", renderFields)
  renderFields()

  if (idx >= 0) {
    list.appendChild(item)
  } else {
    list.insertBefore(item, list.firstChild)
  }
}

function collectConfigFromForm() {
  const cfg = {}
  const meta = state.config.meta || {}
  ;(meta.sections || []).forEach((sec) => {
    ;(sec.fields || []).forEach((f) => {
      const input = state.config.inputs[f.key]
      if (!input) return
      const t = f.type || "text"
      if (t === "bool") {
        cfg[f.key] = !!input.checked
        return
      }
      const val = String(input.value || "").trim()
      if (t === "tags") {
        cfg[f.key] = val ? val.split(",").map((s) => s.trim()).filter(Boolean) : []
        return
      }
      cfg[f.key] = val
    })
  })

  cfg.pusher = state.config.pusherItems
    .map((p) => {
      const t = p.select.value
      if (!t) return null
      const obj = { type: t }
      Object.entries(p.inputs || {}).forEach(([k, input]) => {
        obj[k] = String(input.value || "").trim()
      })
      return obj
    })
    .filter(Boolean)

  return cfg
}

function bind() {
  el("loginForm").addEventListener("submit", handleLogin)
  el("logoutBtn").addEventListener("click", handleLogout)
  el("navVulns").addEventListener("click", () => showView("vulns"))
  el("navConfig").addEventListener("click", () => showView("config"))
  el("searchBtn").addEventListener("click", async () => {
    state.q = el("searchInput").value.trim()
    state.severity = el("severitySelect").value
    state.offset = 0
    await loadList(true)
  })
  el("prevBtn").addEventListener("click", async () => {
    state.offset = Math.max(0, state.offset - state.limit)
    await loadList(false)
  })
  el("nextBtn").addEventListener("click", async () => {
    state.offset = state.offset + state.limit
    await loadList(false)
  })
  el("configReloadBtn").addEventListener("click", loadConfig)
  el("configSaveBtn").addEventListener("click", saveConfig)
}

bind()
bootstrap()

