import { useState, useEffect, useCallback } from "react"

const API = ""  // same-origin via nginx proxy

// ── Palette (Void Space) ──────────────────────────────────────
const C = {
  bg:        "#0d1117",
  surface:   "#161b22",
  border:    "#21262d",
  text:      "#c9d1d9",
  muted:     "#8b949e",
  primary:   "#58a6ff",
  accent:    "#f78166",
  green:     "#3fb950",
  yellow:    "#d29922",
  red:       "#f85149",
}

// ── Shared styles ─────────────────────────────────────────────
const S = {
  sidebar: {
    width: 240, minWidth: 240, background: C.surface, borderRight: `1px solid ${C.border}`,
    display: "flex", flexDirection: "column", height: "100vh", position: "fixed", top: 0, left: 0,
  },
  main: { marginLeft: 240, background: C.bg, minHeight: "100vh", color: C.text },
  topbar: {
    height: 48, borderBottom: `1px solid ${C.border}`, padding: "0 20px",
    display: "flex", alignItems: "center", justifyContent: "space-between",
    background: C.bg, position: "sticky", top: 0, zIndex: 10,
  },
  card: {
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 6, padding: "16px 20px",
  },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 13 },
  th: {
    textAlign: "left", padding: "8px 12px", color: C.muted, fontWeight: 500,
    fontSize: 12, borderBottom: `1px solid ${C.border}`,
  },
  td: { padding: "9px 12px", borderBottom: `1px solid ${C.border}`, verticalAlign: "middle" },
  badge: (color) => ({
    display: "inline-block", fontSize: 11, fontWeight: 500,
    padding: "2px 7px", borderRadius: 4,
    background: color + "22", color,
  }),
  btn: {
    background: "transparent", border: `1px solid ${C.border}`, color: C.text,
    borderRadius: 6, padding: "6px 12px", cursor: "pointer", fontSize: 13,
  },
}

// ── API helpers ───────────────────────────────────────────────
function useApi(path, token, deps = []) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    if (!token) return
    setLoading(true)
    try {
      const r = await fetch(`${API}${path}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (!r.ok) throw new Error(`${r.status}`)
      setData(await r.json())
      setError(null)
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }, [path, token])

  useEffect(() => { load() }, [load, ...deps])
  return { data, loading, error, reload: load }
}

// ── Components ────────────────────────────────────────────────
function NavItem({ label, active, onClick }) {
  return (
    <button onClick={onClick} style={{
      width: "100%", textAlign: "left", padding: "7px 16px",
      background: active ? C.border : "transparent",
      color: active ? C.text : C.muted,
      border: "none", borderRadius: 6, cursor: "pointer",
      fontSize: 13, fontWeight: active ? 500 : 400, marginBottom: 1,
    }}>
      {label}
    </button>
  )
}

function StatCard({ label, value, sub }) {
  return (
    <div style={S.card}>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 600, color: C.text, lineHeight: 1 }}>{value ?? "—"}</div>
      {sub && <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>{sub}</div>}
    </div>
  )
}

function TLPBadge({ level }) {
  const colors = { WHITE: C.muted, GREEN: C.green }
  return <span style={S.badge(colors[level] || C.muted)}>{level}</span>
}

function StatusDot({ status }) {
  const colors = { ok: C.green, error: C.red, running: C.yellow }
  return <span style={{
    display: "inline-block", width: 6, height: 6, borderRadius: "50%",
    background: colors[status] || C.muted, marginRight: 6, flexShrink: 0,
  }} />
}

function Spinner() {
  return <div style={{ color: C.muted, padding: 40, textAlign: "center", fontSize: 13 }}>Loading…</div>
}

// ── Views ─────────────────────────────────────────────────────
function Overview({ token }) {
  const { data: summary, loading } = useApi("/metrics/summary", token)
  const { data: objects } = useApi("/objects?page_size=8", token)

  if (loading) return <Spinner />
  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
        <StatCard label="Total objects" value={summary?.total_objects?.toLocaleString()} />
        <StatCard label="Last 24 hours" value={summary?.objects_last_24h?.toLocaleString()} />
        <StatCard label="Active sources" value={summary?.active_sources} />
        <StatCard label="Open alerts" value={summary?.alerts_new} />
      </div>

      <div style={{ ...S.card, padding: 0 }}>
        <div style={{ padding: "12px 20px", borderBottom: `1px solid ${C.border}`, fontSize: 13, fontWeight: 500 }}>
          Recent objects
        </div>
        <table style={S.table}>
          <thead>
            <tr>
              <th style={S.th}>STIX ID</th>
              <th style={S.th}>Type</th>
              <th style={S.th}>Confidence</th>
              <th style={S.th}>TLP</th>
              <th style={S.th}>Sources</th>
              <th style={S.th}>Created</th>
            </tr>
          </thead>
          <tbody>
            {(objects?.items || []).map(obj => (
              <tr key={obj.stix_id} style={{ color: C.text }}>
                <td style={{ ...S.td, fontFamily: "monospace", fontSize: 12, color: C.muted }}>
                  {obj.stix_id.slice(0, 36)}
                </td>
                <td style={S.td}><span style={S.badge(C.primary)}>{obj.stix_type}</span></td>
                <td style={S.td}>
                  <span style={{ color: obj.confidence >= 70 ? C.green : obj.confidence >= 40 ? C.yellow : C.red }}>
                    {obj.confidence}
                  </span>
                </td>
                <td style={S.td}><TLPBadge level={obj.tlp_level} /></td>
                <td style={{ ...S.td, color: C.muted }}>{obj.source_count}</td>
                <td style={{ ...S.td, color: C.muted, fontSize: 12 }}>
                  {new Date(obj.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ObjectsView({ token }) {
  const [page, setPage] = useState(1)
  const [typeFilter, setTypeFilter] = useState("")
  const [search, setSearch] = useState("")
  const [searchInput, setSearchInput] = useState("")

  const params = new URLSearchParams({ page, page_size: 50 })
  if (typeFilter) params.set("stix_type", typeFilter)
  if (search) params.set("search", search)

  const { data, loading, reload } = useApi(`/objects?${params}`, token, [page, typeFilter, search])
  const types = ["", "indicator", "threat-actor", "attack-pattern", "relationship"]

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(1) }}
          style={{ ...S.btn, background: C.surface, color: C.text }}>
          {types.map(t => <option key={t} value={t}>{t || "All types"}</option>)}
        </select>
        <input
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && (setSearch(searchInput), setPage(1))}
          placeholder="Search objects…"
          style={{
            ...S.btn, flex: 1, outline: "none",
            background: C.surface, color: C.text,
          }}
        />
        <button style={S.btn} onClick={() => { setSearch(searchInput); setPage(1) }}>Search</button>
        <button style={{ ...S.btn, color: C.muted }} onClick={reload}>Refresh</button>
      </div>

      {loading ? <Spinner /> : (
        <>
          <div style={{ ...S.card, padding: 0 }}>
            <table style={S.table}>
              <thead>
                <tr>
                  <th style={S.th}>STIX ID</th>
                  <th style={S.th}>Type</th>
                  <th style={S.th}>Name / Pattern</th>
                  <th style={S.th}>Confidence</th>
                  <th style={S.th}>TLP</th>
                  <th style={S.th}>Created</th>
                </tr>
              </thead>
              <tbody>
                {(data?.items || []).map(obj => (
                  <tr key={obj.stix_id}>
                    <td style={{ ...S.td, fontFamily: "monospace", fontSize: 11, color: C.muted }}>
                      {obj.stix_id.slice(-12)}
                    </td>
                    <td style={S.td}><span style={S.badge(C.primary)}>{obj.stix_type}</span></td>
                    <td style={{ ...S.td, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {obj.stix_data?.name || obj.stix_data?.pattern || "—"}
                    </td>
                    <td style={{ ...S.td, color: obj.confidence >= 70 ? C.green : obj.confidence >= 40 ? C.yellow : C.red }}>
                      {obj.confidence}
                    </td>
                    <td style={S.td}><TLPBadge level={obj.tlp_level} /></td>
                    <td style={{ ...S.td, color: C.muted, fontSize: 12 }}>
                      {new Date(obj.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 12, fontSize: 13, color: C.muted }}>
            <span>{data?.total?.toLocaleString() || 0} objects total</span>
            <div style={{ display: "flex", gap: 8 }}>
              <button style={S.btn} disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</button>
              <span style={{ padding: "6px 8px" }}>Page {page}</span>
              <button style={S.btn} disabled={(data?.items?.length || 0) < 50} onClick={() => setPage(p => p + 1)}>Next</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function AlertsView({ token }) {
  const [statusFilter, setStatusFilter] = useState("new")
  const params = new URLSearchParams({ limit: 50 })
  if (statusFilter) params.set("status", statusFilter)

  const { data: alerts, loading, reload } = useApi(`/alerts?${params}`, token, [statusFilter])

  const ackAlert = async (id, status) => {
    await fetch(`${API}/alerts/${id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    })
    reload()
  }

  const statusColors = { new: C.accent, acked: C.muted, false_positive: C.red }

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {["new", "acked", "false_positive", ""].map(s => (
          <button key={s} onClick={() => setStatusFilter(s)}
            style={{ ...S.btn, color: statusFilter === s ? C.text : C.muted, borderColor: statusFilter === s ? C.border : "transparent" }}>
            {s || "All"}
          </button>
        ))}
      </div>

      {loading ? <Spinner /> : (
        <div style={{ ...S.card, padding: 0 }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Perimeter</th>
                <th style={S.th}>STIX ID</th>
                <th style={S.th}>Source</th>
                <th style={S.th}>Status</th>
                <th style={S.th}>Triggered</th>
                <th style={S.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(alerts || []).map(a => (
                <tr key={a.id}>
                  <td style={{ ...S.td, fontWeight: 500 }}>{a.perimeter_name}</td>
                  <td style={{ ...S.td, fontFamily: "monospace", fontSize: 11, color: C.muted }}>
                    {a.stix_id.slice(-12)}
                  </td>
                  <td style={{ ...S.td, fontSize: 12, color: C.muted, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {a.source_url}
                  </td>
                  <td style={S.td}>
                    <span style={S.badge(statusColors[a.status] || C.muted)}>{a.status}</span>
                  </td>
                  <td style={{ ...S.td, color: C.muted, fontSize: 12 }}>
                    {new Date(a.triggered_at).toLocaleDateString()}
                  </td>
                  <td style={S.td}>
                    {a.status === "new" && (
                      <div style={{ display: "flex", gap: 6 }}>
                        <button style={{ ...S.btn, fontSize: 12, padding: "3px 8px", color: C.green }}
                          onClick={() => ackAlert(a.id, "acked")}>Ack</button>
                        <button style={{ ...S.btn, fontSize: 12, padding: "3px 8px", color: C.red }}
                          onClick={() => ackAlert(a.id, "false_positive")}>FP</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
              {(!alerts || alerts.length === 0) && (
                <tr><td colSpan={6} style={{ ...S.td, textAlign: "center", color: C.muted }}>No alerts</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function SourcesView({ token }) {
  const { data: sources, loading, reload } = useApi("/sources", token)
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ name: "", type: "rss", url: "", frequency_min: 60, category: "known" })

  const createSource = async () => {
    await fetch(`${API}/sources`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(form),
    })
    setShowAdd(false)
    reload()
  }

  const toggleSource = async (id, enabled) => {
    await fetch(`${API}/sources/${id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !enabled }),
    })
    reload()
  }

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
        <button style={{ ...S.btn, color: C.primary }} onClick={() => setShowAdd(v => !v)}>
          {showAdd ? "Cancel" : "+ Add source"}
        </button>
      </div>

      {showAdd && (
        <div style={{ ...S.card, marginBottom: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {[
              ["Name", "name", "text"], ["URL", "url", "text"],
            ].map(([label, key, type]) => (
              <div key={key}>
                <label style={{ display: "block", fontSize: 12, color: C.muted, marginBottom: 4 }}>{label}</label>
                <input type={type} value={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                  style={{ width: "100%", ...S.btn, background: C.bg, boxSizing: "border-box" }} />
              </div>
            ))}
            <div>
              <label style={{ display: "block", fontSize: 12, color: C.muted, marginBottom: 4 }}>Type</label>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
                style={{ width: "100%", ...S.btn, background: C.bg, color: C.text }}>
                {["rss", "html", "pdf_url"].map(t => <option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: "block", fontSize: 12, color: C.muted, marginBottom: 4 }}>Category</label>
              <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
                style={{ width: "100%", ...S.btn, background: C.bg, color: C.text }}>
                {["trusted", "known", "unknown"].map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
          </div>
          <div style={{ marginTop: 12, display: "flex", justifyContent: "flex-end" }}>
            <button style={{ ...S.btn, color: C.primary }} onClick={createSource}>Create</button>
          </div>
        </div>
      )}

      {loading ? <Spinner /> : (
        <div style={{ ...S.card, padding: 0 }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Name</th>
                <th style={S.th}>Type</th>
                <th style={S.th}>Category</th>
                <th style={S.th}>Frequency</th>
                <th style={S.th}>Last run</th>
                <th style={S.th}>Status</th>
                <th style={S.th}>Enabled</th>
              </tr>
            </thead>
            <tbody>
              {(sources || []).map(s => (
                <tr key={s.id}>
                  <td style={{ ...S.td, fontWeight: 500 }}>{s.name}</td>
                  <td style={S.td}><span style={S.badge(C.muted)}>{s.type}</span></td>
                  <td style={S.td}>
                    <span style={S.badge(s.category === "trusted" ? C.green : s.category === "known" ? C.primary : C.muted)}>
                      {s.category}
                    </span>
                  </td>
                  <td style={{ ...S.td, color: C.muted }}>{s.frequency_min}m</td>
                  <td style={{ ...S.td, color: C.muted, fontSize: 12 }}>
                    {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "—"}
                  </td>
                  <td style={S.td}>
                    {s.last_status ? (
                      <span style={{ display: "flex", alignItems: "center" }}>
                        <StatusDot status={s.last_status} />
                        <span style={{ fontSize: 12, color: C.muted }}>{s.last_status}</span>
                      </span>
                    ) : <span style={{ color: C.muted }}>—</span>}
                  </td>
                  <td style={S.td}>
                    <button style={{ ...S.btn, fontSize: 12, padding: "3px 8px", color: s.enabled ? C.green : C.muted }}
                      onClick={() => toggleSource(s.id, s.enabled)}>
                      {s.enabled ? "On" : "Off"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function MetricsView({ token }) {
  const [hours, setHours] = useState(24)
  const { data: summary } = useApi("/metrics/summary", token)
  const { data: metrics, loading } = useApi(`/metrics?hours=${hours}&limit=200`, token, [hours])

  const grouped = {}
  ;(metrics || []).forEach(m => {
    const key = `${m.module}.${m.metric}`
    if (!grouped[key]) grouped[key] = { module: m.module, metric: m.metric, points: [] }
    grouped[key].points.push({ t: new Date(m.recorded_at), v: m.value })
  })

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
        <StatCard label="Total objects" value={summary?.total_objects?.toLocaleString()} />
        <StatCard label="Active sources" value={summary?.active_sources} />
        <StatCard label="Open alerts" value={summary?.alerts_new} />
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {[6, 24, 72, 168].map(h => (
          <button key={h} style={{ ...S.btn, color: hours === h ? C.text : C.muted, borderColor: hours === h ? C.border : "transparent" }}
            onClick={() => setHours(h)}>{h}h</button>
        ))}
      </div>

      {loading ? <Spinner /> : (
        <div style={{ ...S.card, padding: 0 }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Module</th>
                <th style={S.th}>Metric</th>
                <th style={S.th}>Total</th>
                <th style={S.th}>Last</th>
                <th style={S.th}>Recorded at</th>
              </tr>
            </thead>
            <tbody>
              {Object.values(grouped).map(g => {
                const total = g.points.reduce((s, p) => s + p.v, 0)
                const last = g.points[0]
                return (
                  <tr key={`${g.module}.${g.metric}`}>
                    <td style={{ ...S.td, fontFamily: "monospace", fontSize: 12, color: C.muted }}>{g.module}</td>
                    <td style={{ ...S.td, fontSize: 12 }}>{g.metric}</td>
                    <td style={{ ...S.td, fontWeight: 500 }}>{Math.round(total).toLocaleString()}</td>
                    <td style={{ ...S.td, color: C.muted }}>{last?.v}</td>
                    <td style={{ ...S.td, color: C.muted, fontSize: 12 }}>
                      {last ? last.t.toLocaleString() : "—"}
                    </td>
                  </tr>
                )
              })}
              {Object.keys(grouped).length === 0 && (
                <tr><td colSpan={5} style={{ ...S.td, textAlign: "center", color: C.muted }}>No metrics in this window</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Login ─────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")

  const submit = async (e) => {
    e.preventDefault()
    try {
      const r = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      })
      if (!r.ok) { setError("Invalid credentials"); return }
      const { access_token } = await r.json()
      onLogin(access_token)
    } catch { setError("Connection error") }
  }

  return (
    <div style={{ background: C.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ ...S.card, width: 320 }}>
        <div style={{ fontSize: 16, fontWeight: 500, marginBottom: 20, color: C.text }}>CTI Aggregator</div>
        <form onSubmit={submit}>
          <div style={{ marginBottom: 12 }}>
            <label style={{ display: "block", fontSize: 12, color: C.muted, marginBottom: 4 }}>Email</label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)}
              style={{ width: "100%", ...S.btn, background: C.bg, color: C.text, boxSizing: "border-box" }} />
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: "block", fontSize: 12, color: C.muted, marginBottom: 4 }}>Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)}
              style={{ width: "100%", ...S.btn, background: C.bg, color: C.text, boxSizing: "border-box" }} />
          </div>
          {error && <div style={{ fontSize: 12, color: C.red, marginBottom: 12 }}>{error}</div>}
          <button type="submit" style={{ ...S.btn, width: "100%", color: C.primary, borderColor: C.primary }}>
            Sign in
          </button>
        </form>
      </div>
    </div>
  )
}

// ── App ───────────────────────────────────────────────────────
const VIEWS = ["Overview", "Objects", "Alerts", "Sources", "Metrics"]

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem("cti_token") || "")
  const [view, setView] = useState("Overview")

  const login = (t) => { sessionStorage.setItem("cti_token", t); setToken(t) }
  const logout = () => { sessionStorage.removeItem("cti_token"); setToken("") }

  if (!token) return <Login onLogin={login} />

  const ViewComponent = { Overview, Objects: ObjectsView, Alerts: AlertsView, Sources: SourcesView, Metrics: MetricsView }[view]

  return (
    <div style={{ display: "flex", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", fontSize: 14, color: C.text }}>
      <div style={S.sidebar}>
        <div style={{ padding: "14px 16px", borderBottom: `1px solid ${C.border}`, fontSize: 14, fontWeight: 600, color: C.text }}>
          CTI Aggregator
        </div>
        <nav style={{ flex: 1, padding: "8px 8px" }}>
          {VIEWS.map(v => <NavItem key={v} label={v} active={view === v} onClick={() => setView(v)} />)}
        </nav>
        <div style={{ padding: "12px 16px", borderTop: `1px solid ${C.border}` }}>
          <button style={{ ...S.btn, width: "100%", color: C.muted, fontSize: 12 }} onClick={logout}>Sign out</button>
        </div>
      </div>

      <div style={S.main}>
        <div style={S.topbar}>
          <span style={{ fontSize: 14, fontWeight: 500 }}>{view}</span>
        </div>
        <ViewComponent token={token} />
      </div>
    </div>
  )
}
