import { useState, useEffect, useCallback, useRef } from "react"

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
  const colors = { WHITE: C.muted, GREEN: "#3fb950", AMBER: "#d29922", RED: "#f85149" }
  return <span style={S.badge(colors[level] || C.muted)}>TLP:{level}</span>
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

// ── Helpers ───────────────────────────────────────────────────

function inferIndicatorType(pattern) {
  if (!pattern) return null
  if (pattern.includes("ipv4-addr")) return "ipv4"
  if (pattern.includes("ipv6-addr")) return "ipv6"
  if (pattern.includes("domain-name")) return "domain"
  if (pattern.includes("url:value")) return "url"
  if (pattern.includes("email-addr")) return "email"
  if (pattern.includes("SHA256")) return "hash"
  if (pattern.includes("SHA1")) return "hash"
  if (pattern.includes("MD5")) return "hash"
  if (/CVE-\d{4}-\d+/.test(pattern)) return "cve"
  return null
}

// CVE detection — priority order:
//   1. explicit x_cti_cve_id field (new format)
//   2. CVE ID embedded in the STIX pattern ([url:value = '...cve.org...CVE-YYYY-NNNN'])
//   3. legacy: name starts with "CVE-"
function getCveId(obj) {
  if (!obj || obj.stix_type !== "indicator") return null
  const d = obj.stix_data || {}
  if (d.x_cti_cve_id) return d.x_cti_cve_id
  const patternMatch = /CVE-\d{4}-\d+/.exec(d.pattern || "")
  if (patternMatch) return patternMatch[0]
  const nameMatch = /^CVE-\d{4}-\d+/.exec(d.name || "")
  if (nameMatch) return nameMatch[0]
  return null
}

function isCVE(obj) {
  return getCveId(obj) !== null
}

function cvssColor(score) {
  if (score == null) return "#8b949e"
  if (score >= 9.0) return "#f85149"   // Critical — red
  if (score >= 7.0) return "#d29922"   // High — orange
  if (score >= 4.0) return "#e3b341"   // Medium — yellow
  if (score >= 0.1) return "#3fb950"   // Low — green
  return "#8b949e"                     // Unknown — grey
}

// CVSS score — prefer enrichment (authoritative NVD data), fall back to LLM-extracted
function getCvssScore(obj) {
  return (
    obj?.stix_data?.x_cti_enrichment?.nvd?.cvss_score ??
    obj?.stix_data?.x_cti_cvss_score ??
    null
  )
}

// Severity — prefer enrichment, fall back to LLM-extracted
function getSeverity(obj) {
  return (
    obj?.stix_data?.x_cti_enrichment?.nvd?.cvss_severity ??
    obj?.stix_data?.x_cti_severity ??
    null
  )
}

function objectDisplayName(obj) {
  // For CVEs, prefer the LLM-generated short label (e.g. "RCE Adobe"),
  // falling back to the CVE ID if no descriptive name is available.
  if (isCVE(obj)) {
    const name = obj.stix_data?.name || ""
    // If the name is already just the CVE ID (legacy format), keep it as-is.
    return name || getCveId(obj) || "—"
  }
  return obj.stix_data?.name || obj.stix_data?.pattern || "—"
}

// ── Views ─────────────────────────────────────────────────────

function IncidentBanner({ token }) {
  const { data } = useApi("/metrics/incidents", token)
  const live = data?.source === "grafana"

  const pill = (label, value, color) => (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      background: C.surface, border: `1px solid ${live ? color + "44" : C.border}`,
      borderRadius: 8, padding: "12px 32px", minWidth: 140,
    }}>
      <span style={{ fontSize: 28, fontWeight: 700, color: live ? color : C.muted, lineHeight: 1 }}>
        {live ? (value ?? "0") : "—"}
      </span>
      <span style={{ fontSize: 11, color: C.muted, marginTop: 5, textTransform: "uppercase", letterSpacing: "0.08em" }}>
        {label}
      </span>
    </div>
  )

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12, padding: "16px 24px",
      borderBottom: `1px solid ${C.border}`, background: C.bg,
      justifyContent: "space-between",
    }}>
      <div style={{ fontSize: 12, color: C.muted, fontWeight: 500 }}>
        Incidents
        {live && <span style={{ marginLeft: 8, color: C.green, fontSize: 11 }}>● Grafana</span>}
      </div>
      <div style={{ display: "flex", gap: 12 }}>
        {pill("New", data?.new, C.red)}
        {pill("Acknowledged", data?.acknowledged, C.yellow)}
        {pill("Resolved", data?.resolved, C.green)}
      </div>
    </div>
  )
}

function Overview({ token }) {
  const { data: summary, loading } = useApi("/metrics/summary", token)
  const { data: alerts } = useApi("/alerts?page_size=5&status=new", token)
  const { data: cves } = useApi("/metrics/recent-cves", token)

  if (loading) return <Spinner />

  return (
    <div>
      <IncidentBanner token={token} />
      <div style={{ padding: 24 }}>

        {/* KPI row */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
          <StatCard label="Total objects" value={summary?.total_objects?.toLocaleString()} />
          <StatCard label="Last 24 hours" value={summary?.objects_last_24h?.toLocaleString()} />
          <StatCard label="Active sources" value={summary?.active_sources} />
          <StatCard label="Open alerts" value={summary?.alerts_new} />
        </div>

        {/* Widgets row */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

          {/* Recent alerts */}
          <div style={{ ...S.card, padding: 0 }}>
            <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, fontSize: 13, fontWeight: 500 }}>
              Recent alerts
            </div>
            {(alerts?.items || []).length === 0
              ? <div style={{ padding: 16, fontSize: 12, color: C.muted }}>No open alerts.</div>
              : (alerts?.items || []).map(a => (
                <div key={a.id} style={{
                  padding: "10px 16px", borderBottom: `1px solid ${C.border}`,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                    <span style={{ fontSize: 12, fontWeight: 500 }}>{a.perimeter_name}</span>
                    <SeverityBadge severity={a.severity} />
                  </div>
                  <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace" }}>
                    {(a.stix_id || a.stix_object_id || "").slice(0, 40)}
                  </div>
                  <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>
                    {new Date(a.triggered_at).toLocaleString()}
                  </div>
                </div>
              ))
            }
          </div>

          {/* Last CVEs */}
          <div style={{ ...S.card, padding: 0 }}>
            <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, fontSize: 13, fontWeight: 500 }}>
              Last CVEs
            </div>
            {(cves || []).length === 0
              ? <div style={{ padding: 16, fontSize: 12, color: C.muted }}>No CVEs yet.</div>
              : (cves || []).map(c => (
                <div key={c.stix_id} style={{ padding: "10px 16px", borderBottom: `1px solid ${C.border}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                      <span style={S.badge(cvssColor(c.cvss_score))}>{c.cve_id}</span>
                      {c.cvss_score != null && (
                        <span style={{ fontSize: 11, fontWeight: 600, color: cvssColor(c.cvss_score) }}>
                          {c.cvss_score.toFixed(1)}
                        </span>
                      )}
                    </span>
                    <span style={{
                      fontSize: 12, fontWeight: 600,
                      color: c.confidence >= 70 ? C.green : c.confidence >= 40 ? C.yellow : C.red,
                    }}>{c.confidence}</span>
                  </div>
                  {c.description && (
                    <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.4,
                      overflow: "hidden", display: "-webkit-box",
                      WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                      {c.description}
                    </div>
                  )}
                  <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>
                    {new Date(c.created_at).toLocaleDateString()}
                  </div>
                </div>
              ))
            }
          </div>

        </div>
      </div>
    </div>
  )
}

function ObjectsView({ token }) {
  const [page, setPage] = useState(1)
  const [typeFilter, setTypeFilter] = useState("")
  const [search, setSearch] = useState("")
  const [searchInput, setSearchInput] = useState("")
  const [selectedObj, setSelectedObj] = useState(null)

  const params = new URLSearchParams({ page, page_size: 50 })
  if (typeFilter) params.set("stix_type", typeFilter)
  if (search) params.set("search", search)

  const { data, loading, reload } = useApi(`/objects?${params}`, token, [page, typeFilter, search])
  const types = ["", "indicator", "threat-actor", "attack-pattern", "relationship"]

  const fetchAndSelect = async (stix_id) => {
    try {
      const r = await fetch(`${API}/objects/${stix_id}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (r.ok) setSelectedObj(await r.json())
    } catch { /* ignore */ }
  }

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
                  <th style={S.th}>Enriched</th>
                  <th style={S.th}>Created</th>
                </tr>
              </thead>
              <tbody>
                {(data?.items || []).map(obj => (
                  <tr
                    key={obj.stix_id}
                    onClick={() => fetchAndSelect(obj.stix_id)}
                    style={{ cursor: "pointer" }}
                    onMouseEnter={e => e.currentTarget.style.background = C.border}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  >
                    <td style={{ ...S.td, fontFamily: "monospace", fontSize: 11, color: C.muted }}>
                      {obj.stix_id.slice(-12)}
                    </td>
                    <td style={S.td}><span style={S.badge(C.primary)}>{obj.stix_type}</span></td>
                    <td style={{ ...S.td, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {isCVE(obj) ? (
                        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                          <span style={S.badge(cvssColor(getCvssScore(obj)))}>{objectDisplayName(obj)}</span>
                          <span style={{ fontSize: 10, fontFamily: "monospace", color: C.muted }}>
                            {getCveId(obj)}
                          </span>
                          {getCvssScore(obj) != null && (
                            <span style={{ fontSize: 11, fontWeight: 600, color: cvssColor(getCvssScore(obj)) }}>
                              {getCvssScore(obj).toFixed(1)}
                            </span>
                          )}
                        </span>
                      ) : objectDisplayName(obj)}
                    </td>
                    <td style={{ ...S.td, color: obj.confidence >= 70 ? C.green : obj.confidence >= 40 ? C.yellow : C.red }}>
                      {obj.confidence}
                    </td>
                    <td style={S.td}><TLPBadge level={obj.tlp_level} /></td>
                    <td style={S.td}>
                      {obj.stix_data?.x_cti_enrichment
                        ? <span style={S.badge(C.green)}>Enrichi</span>
                        : null
                      }
                    </td>
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

      <ObjectDrawer obj={selectedObj} token={token} onClose={() => setSelectedObj(null)} />
    </div>
  )
}

const SEVERITY_COLORS = {
  critical: C.red,
  high: C.accent,
  medium: C.yellow,
  low: C.green,
}

function SeverityBadge({ level }) {
  return <span style={S.badge(SEVERITY_COLORS[level] || C.muted)}>{level}</span>
}

function AlertsView({ token }) {
  const [statusFilter, setStatusFilter] = useState("new")
  const [severityFilter, setSeverityFilter] = useState("")

  const params = new URLSearchParams({ limit: 50 })
  if (statusFilter) params.set("status", statusFilter)
  if (severityFilter) params.set("severity", severityFilter)

  const { data: alerts, loading, reload } = useApi(
    `/alerts?${params}`, token, [statusFilter, severityFilter]
  )

  const patchAlert = async (id, patch) => {
    await fetch(`${API}/alerts/${id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    })
    reload()
  }

  const statusColors = { new: C.accent, acked: C.muted, false_positive: C.red }

  return (
    <div style={{ padding: 24 }}>
      {/* Status filter */}
      <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
        {["new", "acked", "false_positive", ""].map(s => (
          <button key={s} onClick={() => setStatusFilter(s)}
            style={{ ...S.btn, color: statusFilter === s ? C.text : C.muted, borderColor: statusFilter === s ? C.border : "transparent" }}>
            {s || "All"}
          </button>
        ))}
      </div>

      {/* Severity filter */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, alignItems: "center" }}>
        <span style={{ fontSize: 12, color: C.muted }}>Severity:</span>
        {["", "critical", "high", "medium", "low"].map(sv => (
          <button key={sv} onClick={() => setSeverityFilter(sv)}
            style={{
              ...S.btn, fontSize: 12, padding: "3px 10px",
              color: severityFilter === sv ? (SEVERITY_COLORS[sv] || C.text) : C.muted,
              borderColor: severityFilter === sv ? C.border : "transparent",
            }}>
            {sv || "All"}
          </button>
        ))}
      </div>

      {loading ? <Spinner /> : (
        <div style={{ ...S.card, padding: 0 }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Severity</th>
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
                  <td style={S.td}><SeverityBadge level={a.severity} /></td>
                  <td style={{ ...S.td, fontWeight: 500 }}>{a.perimeter_name}</td>
                  <td style={{ ...S.td, fontFamily: "monospace", fontSize: 11, color: C.muted }}>
                    {a.stix_id.slice(-12)}
                  </td>
                  <td style={{ ...S.td, fontSize: 12, color: C.muted, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {a.source_url}
                  </td>
                  <td style={S.td}>
                    <span style={S.badge(statusColors[a.status] || C.muted)}>{a.status}</span>
                  </td>
                  <td style={{ ...S.td, color: C.muted, fontSize: 12 }}>
                    {new Date(a.triggered_at).toLocaleDateString()}
                  </td>
                  <td style={S.td}>
                    <div style={{ display: "flex", gap: 4 }}>
                      {a.status === "new" && (
                        <>
                          <button style={{ ...S.btn, fontSize: 11, padding: "2px 7px", color: C.green }}
                            onClick={() => patchAlert(a.id, { status: "acked" })}>Ack</button>
                          <button style={{ ...S.btn, fontSize: 11, padding: "2px 7px", color: C.red }}
                            onClick={() => patchAlert(a.id, { status: "false_positive" })}>FP</button>
                        </>
                      )}
                      {/* Escalate severity */}
                      {a.severity !== "critical" && (
                        <button style={{ ...S.btn, fontSize: 11, padding: "2px 7px", color: C.accent }}
                          onClick={() => {
                            const next = { low: "medium", medium: "high", high: "critical" }[a.severity]
                            if (next) patchAlert(a.id, { severity: next })
                          }}>↑</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {(!alerts || alerts.length === 0) && (
                <tr><td colSpan={7} style={{ ...S.td, textAlign: "center", color: C.muted }}>No alerts</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Perimeters ────────────────────────────────────────────────
function tagListToArray(str) {
  return str.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
}

function arrayToTagList(arr) {
  return (arr || []).join("\n")
}

const EMPTY_PERIMETER = {
  name: "", description: "", severity: "medium",
  ioc_values: "", sectors: "", geo_countries: "",
  software_products: "", ip_ranges: "", webhook_url: "", enabled: true,
}

function PerimeterForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState({
    ...EMPTY_PERIMETER,
    ...Object.fromEntries(
      Object.entries(initial || {}).map(([k, v]) =>
        Array.isArray(v) ? [k, arrayToTagList(v)] : [k, v ?? ""]
      )
    ),
  })

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))
  const setChk = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.checked }))

  const submit = () => {
    onSave({
      name: form.name,
      description: form.description || null,
      severity: form.severity,
      ioc_values: tagListToArray(form.ioc_values),
      sectors: tagListToArray(form.sectors),
      geo_countries: tagListToArray(form.geo_countries),
      software_products: tagListToArray(form.software_products),
      ip_ranges: tagListToArray(form.ip_ranges),
      webhook_url: form.webhook_url || null,
      enabled: form.enabled,
    })
  }

  const inputStyle = { width: "100%", ...S.btn, background: C.bg, color: C.text, boxSizing: "border-box" }
  const taStyle = { ...inputStyle, height: 64, resize: "vertical", fontFamily: "monospace", fontSize: 12 }
  const labelStyle = { display: "block", fontSize: 12, color: C.muted, marginBottom: 4 }

  return (
    <div style={{ ...S.card, marginBottom: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div>
          <label style={labelStyle}>Name *</label>
          <input value={form.name} onChange={set("name")} style={inputStyle} />
        </div>
        <div>
          <label style={labelStyle}>Severity par défaut</label>
          <select value={form.severity} onChange={set("severity")}
            style={{ ...inputStyle, color: SEVERITY_COLORS[form.severity] || C.text }}>
            {["low", "medium", "high", "critical"].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div style={{ gridColumn: "1 / -1" }}>
          <label style={labelStyle}>Description</label>
          <input value={form.description} onChange={set("description")} style={inputStyle} />
        </div>
        <div>
          <label style={labelStyle}>IoC values (IPs, domaines, hashes…)</label>
          <textarea value={form.ioc_values} onChange={set("ioc_values")} style={taStyle} placeholder="1.2.3.4&#10;evil.com" />
        </div>
        <div>
          <label style={labelStyle}>Plages IP clients</label>
          <textarea value={form.ip_ranges} onChange={set("ip_ranges")} style={taStyle} placeholder="10.0.0.0/8&#10;192.168.0.0/16" />
        </div>
        <div>
          <label style={labelStyle}>Secteurs d'activité</label>
          <textarea value={form.sectors} onChange={set("sectors")} style={taStyle} placeholder="finance&#10;santé&#10;énergie" />
        </div>
        <div>
          <label style={labelStyle}>Pays (ciblés / origine)</label>
          <textarea value={form.geo_countries} onChange={set("geo_countries")} style={taStyle} placeholder="FR&#10;US&#10;CN" />
        </div>
        <div>
          <label style={labelStyle}>Logiciels / produits surveillés</label>
          <textarea value={form.software_products} onChange={set("software_products")} style={taStyle} placeholder="Apache&#10;Windows Server&#10;Cisco IOS" />
        </div>
        <div>
          <label style={labelStyle}>Webhook URL</label>
          <input value={form.webhook_url} onChange={set("webhook_url")} style={inputStyle} placeholder="https://…" />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={form.enabled} onChange={setChk("enabled")} id="peri-enabled" />
          <label htmlFor="peri-enabled" style={{ fontSize: 13, color: C.text, cursor: "pointer" }}>Activé</label>
        </div>
      </div>
      <div style={{ marginTop: 14, display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <button style={{ ...S.btn, color: C.muted }} onClick={onCancel}>Annuler</button>
        <button style={{ ...S.btn, color: C.primary, borderColor: C.primary }} onClick={submit}>
          Enregistrer
        </button>
      </div>
    </div>
  )
}

function PerimetersView({ token }) {
  const { data: perimeters, loading, reload } = useApi("/perimeters", token)
  const [mode, setMode] = useState(null) // null | "create" | {id, ...perimeter}

  const apiCall = async (method, path, body) => {
    await fetch(`${API}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    })
    reload()
    setMode(null)
  }

  const deletePerimeter = async (id) => {
    if (!confirm("Supprimer ce périmètre ?")) return
    await fetch(`${API}/perimeters/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    })
    reload()
  }

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
        <button style={{ ...S.btn, color: C.primary }}
          onClick={() => setMode(mode === "create" ? null : "create")}>
          {mode === "create" ? "Annuler" : "+ Nouveau périmètre"}
        </button>
      </div>

      {mode === "create" && (
        <PerimeterForm
          onSave={data => apiCall("POST", "/perimeters", data)}
          onCancel={() => setMode(null)}
        />
      )}

      {typeof mode === "object" && mode !== null && (
        <PerimeterForm
          initial={mode}
          onSave={data => apiCall("PATCH", `/perimeters/${mode.id}`, data)}
          onCancel={() => setMode(null)}
        />
      )}

      {loading ? <Spinner /> : (
        <div style={{ ...S.card, padding: 0 }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Nom</th>
                <th style={S.th}>Severity</th>
                <th style={S.th}>IoC</th>
                <th style={S.th}>Secteurs</th>
                <th style={S.th}>Pays</th>
                <th style={S.th}>Logiciels</th>
                <th style={S.th}>Plages IP</th>
                <th style={S.th}>État</th>
                <th style={S.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(perimeters || []).map(p => (
                <tr key={p.id}>
                  <td style={{ ...S.td, fontWeight: 500 }}>{p.name}</td>
                  <td style={S.td}><SeverityBadge level={p.severity} /></td>
                  <td style={{ ...S.td, color: C.muted, fontSize: 12 }}>{p.ioc_values.length}</td>
                  <td style={{ ...S.td, fontSize: 12, color: C.muted, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {p.sectors.join(", ") || "—"}
                  </td>
                  <td style={{ ...S.td, fontSize: 12, color: C.muted }}>
                    {p.geo_countries.join(", ") || "—"}
                  </td>
                  <td style={{ ...S.td, fontSize: 12, color: C.muted, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {p.software_products.join(", ") || "—"}
                  </td>
                  <td style={{ ...S.td, fontSize: 12, color: C.muted }}>
                    {p.ip_ranges.length > 0 ? p.ip_ranges.length + " plage(s)" : "—"}
                  </td>
                  <td style={S.td}>
                    <span style={S.badge(p.enabled ? C.green : C.muted)}>
                      {p.enabled ? "actif" : "inactif"}
                    </span>
                  </td>
                  <td style={S.td}>
                    <div style={{ display: "flex", gap: 4 }}>
                      <button style={{ ...S.btn, fontSize: 11, padding: "2px 8px", color: C.primary }}
                        onClick={() => setMode(p)}>Éditer</button>
                      <button style={{ ...S.btn, fontSize: 11, padding: "2px 8px", color: C.red }}
                        onClick={() => deletePerimeter(p.id)}>✕</button>
                    </div>
                  </td>
                </tr>
              ))}
              {(!perimeters || perimeters.length === 0) && (
                <tr><td colSpan={9} style={{ ...S.td, textAlign: "center", color: C.muted }}>Aucun périmètre configuré</td></tr>
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

  // Upload state
  const [showUpload, setShowUpload] = useState(false)
  const [uploadFile, setUploadFile] = useState(null)
  const [uploadForm, setUploadForm] = useState({ name: "", category: "known", tlp_level: "WHITE" })
  const [uploadStatus, setUploadStatus] = useState(null) // null | "uploading" | "done" | "error"
  const [dragOver, setDragOver] = useState(false)

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

  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) {
      setUploadFile(f)
      if (!uploadForm.name) setUploadForm(u => ({ ...u, name: f.name }))
    }
  }

  const submitUpload = async () => {
    if (!uploadFile || !uploadForm.name) return
    setUploadStatus("uploading")
    const fd = new FormData()
    fd.append("file", uploadFile)
    fd.append("name", uploadForm.name)
    fd.append("category", uploadForm.category)
    fd.append("tlp_level", uploadForm.tlp_level)
    try {
      const r = await fetch(`${API}/sources/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: fd,
      })
      if (r.ok) {
        setUploadStatus("done")
        reload()
        setTimeout(() => { setShowUpload(false); setUploadFile(null); setUploadStatus(null) }, 2000)
      } else {
        setUploadStatus("error")
      }
    } catch { setUploadStatus("error") }
  }

  const inputStyle = { width: "100%", ...S.btn, background: C.bg, color: C.text, boxSizing: "border-box" }
  const labelStyle = { display: "block", fontSize: 12, color: C.muted, marginBottom: 4 }

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginBottom: 16 }}>
        <button style={{ ...S.btn, color: C.primary }} onClick={() => { setShowAdd(v => !v); setShowUpload(false) }}>
          {showAdd ? "Annuler" : "+ Add source"}
        </button>
        <button style={{ ...S.btn, color: C.primary }} onClick={() => { setShowUpload(v => !v); setShowAdd(false) }}>
          {showUpload ? "Annuler" : "↑ Upload fichier"}
        </button>
      </div>

      {/* URL source form */}
      {showAdd && (
        <div style={{ ...S.card, marginBottom: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {[["Name", "name", "text"], ["URL", "url", "text"]].map(([label, key, type]) => (
              <div key={key}>
                <label style={labelStyle}>{label}</label>
                <input type={type} value={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                  style={inputStyle} />
              </div>
            ))}
            <div>
              <label style={labelStyle}>Type</label>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
                style={{ ...inputStyle }}>
                {["rss", "html", "pdf_url"].map(t => <option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label style={labelStyle}>Category</label>
              <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
                style={{ ...inputStyle }}>
                {["trusted", "known", "unknown"].map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
          </div>
          <div style={{ marginTop: 12, display: "flex", justifyContent: "flex-end" }}>
            <button style={{ ...S.btn, color: C.primary }} onClick={createSource}>Create</button>
          </div>
        </div>
      )}

      {/* File upload form */}
      {showUpload && (
        <div style={{ ...S.card, marginBottom: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 12, color: C.text }}>
            Upload un fichier — PDF, TXT ou HTML
          </div>

          {/* Drag & drop zone */}
          <div
            onDragOver={e => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => document.getElementById("file-input").click()}
            style={{
              border: `2px dashed ${dragOver ? C.primary : C.border}`,
              borderRadius: 6, padding: 24, textAlign: "center",
              cursor: "pointer", marginBottom: 14,
              background: dragOver ? C.primary + "11" : "transparent",
              transition: "all 0.15s",
            }}
          >
            <input
              id="file-input" type="file" accept=".pdf,.txt,.html,.htm"
              style={{ display: "none" }}
              onChange={e => {
                const f = e.target.files?.[0]
                if (f) { setUploadFile(f); if (!uploadForm.name) setUploadForm(u => ({ ...u, name: f.name })) }
              }}
            />
            {uploadFile ? (
              <div>
                <div style={{ color: C.green, fontWeight: 500 }}>{uploadFile.name}</div>
                <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>
                  {(uploadFile.size / 1024).toFixed(1)} KB
                </div>
              </div>
            ) : (
              <div style={{ color: C.muted, fontSize: 13 }}>
                Glisser-déposer un fichier ici, ou cliquer pour parcourir
                <div style={{ fontSize: 11, marginTop: 4 }}>.pdf · .txt · .html</div>
              </div>
            )}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <div style={{ gridColumn: "1 / -1" }}>
              <label style={labelStyle}>Nom de la source *</label>
              <input value={uploadForm.name} onChange={e => setUploadForm(u => ({ ...u, name: e.target.value }))}
                style={inputStyle} placeholder="Ex: Rapport ANSSI 2026-Q1" />
            </div>
            <div>
              <label style={labelStyle}>Catégorie</label>
              <select value={uploadForm.category} onChange={e => setUploadForm(u => ({ ...u, category: e.target.value }))}
                style={{ ...inputStyle }}>
                {["trusted", "known", "unknown"].map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label style={labelStyle}>TLP</label>
              <select value={uploadForm.tlp_level} onChange={e => setUploadForm(u => ({ ...u, tlp_level: e.target.value }))}
                style={{ ...inputStyle }}>
                {["WHITE", "GREEN"].map(t => <option key={t}>{t}</option>)}
              </select>
            </div>
          </div>

          <div style={{ marginTop: 14, display: "flex", alignItems: "center", gap: 12 }}>
            <button
              style={{ ...S.btn, color: C.primary, borderColor: C.primary }}
              onClick={submitUpload}
              disabled={!uploadFile || !uploadForm.name || uploadStatus === "uploading"}
            >
              {uploadStatus === "uploading" ? "Envoi en cours…" : "Envoyer"}
            </button>
            {uploadStatus === "done" && <span style={{ fontSize: 12, color: C.green }}>Fichier envoyé — pipeline démarré</span>}
            {uploadStatus === "error" && <span style={{ fontSize: 12, color: C.red }}>Erreur lors de l'upload</span>}
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
                  <td style={{ ...S.td, fontWeight: 500 }}>
                    {s.name}
                    {s.type === "pdf_upload" && s.config?.original_filename && (
                      <div style={{ fontSize: 11, color: C.muted, fontWeight: 400 }}>
                        {s.config.original_filename}
                      </div>
                    )}
                  </td>
                  <td style={S.td}><span style={S.badge(s.type === "pdf_upload" ? C.accent : C.muted)}>{s.type}</span></td>
                  <td style={S.td}>
                    <span style={S.badge(s.category === "trusted" ? C.green : s.category === "known" ? C.primary : C.muted)}>
                      {s.category}
                    </span>
                  </td>
                  <td style={{ ...S.td, color: C.muted }}>
                    {s.type === "pdf_upload" ? "—" : `${s.frequency_min}m`}
                  </td>
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

// ── Object Drawer ─────────────────────────────────────────────
function ObjectDrawer({ obj: initialObj, token, onClose }) {
  const [enrichStatus, setEnrichStatus] = useState(null) // null | "queued" | "done" | "error"
  const [obj, setObj] = useState(initialObj)

  // Keep in sync if parent re-selects the same object
  useEffect(() => { setObj(initialObj); setEnrichStatus(null) }, [initialObj?.stix_id])

  if (!obj) return null

  const enrichment = obj.stix_data?.x_cti_enrichment
  const vt = enrichment?.virustotal
  const shodan = enrichment?.shodan
  const indicatorType = obj.stix_type === "indicator" ? inferIndicatorType(obj.stix_data?.pattern) : null

  const triggerEnrich = async () => {
    try {
      const r = await fetch(`${API}/objects/${obj.stix_id}/enrich`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!r.ok) { setEnrichStatus("error"); return }
      setEnrichStatus("queued")

      // Poll for results every 2s, up to 30s
      let attempts = 0
      const poll = setInterval(async () => {
        attempts++
        try {
          const pr = await fetch(`${API}/objects/${obj.stix_id}`, {
            headers: { Authorization: `Bearer ${token}` }
          })
          if (pr.ok) {
            const fresh = await pr.json()
            if (fresh.stix_data?.x_cti_enrichment) {
              setObj(fresh)
              setEnrichStatus("done")
              clearInterval(poll)
              return
            }
          }
        } catch { /* keep polling */ }
        if (attempts >= 15) { clearInterval(poll); setEnrichStatus("timeout") }
      }, 2000)
    } catch { setEnrichStatus("error") }
  }

  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose} style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 40,
      }} />

      {/* Panel */}
      <div style={{
        position: "fixed", top: 0, right: 0, bottom: 0, width: 540,
        background: C.surface, borderLeft: `1px solid ${C.border}`,
        zIndex: 50, display: "flex", flexDirection: "column",
        overflowY: "auto",
      }}>
        {/* Header */}
        <div style={{
          padding: "14px 20px", borderBottom: `1px solid ${C.border}`,
          display: "flex", justifyContent: "space-between", alignItems: "center",
          position: "sticky", top: 0, background: C.surface, zIndex: 1,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={S.badge(C.primary)}>{obj.stix_type}</span>
            <TLPBadge level={obj.tlp_level} />
            <span style={{ fontFamily: "monospace", fontSize: 11, color: C.muted }}>
              {obj.stix_id}
            </span>
          </div>
          <button onClick={onClose} style={{ ...S.btn, padding: "3px 8px", fontSize: 12, color: C.muted }}>✕</button>
        </div>

        <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
          {/* Object info */}
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
            {isCVE(obj) && (
              <span style={{ fontSize: 16, fontWeight: 600, color: cvssColor(getCvssScore(obj)) }}>
                {objectDisplayName(obj)}
              </span>
            )}
            {isCVE(obj) && (
              <span style={{ fontFamily: "monospace", fontSize: 12, color: C.muted }}>
                {getCveId(obj)}
              </span>
            )}
            {isCVE(obj) && getCvssScore(obj) != null && (
              <span style={S.badge(cvssColor(getCvssScore(obj)))}>
                CVSS {getCvssScore(obj).toFixed(1)} — {getSeverity(obj) || "?"}
              </span>
            )}
            {isCVE(obj) && getCvssScore(obj) == null && getSeverity(obj) && (
              <span style={S.badge(cvssColor(
                getSeverity(obj) === "CRITICAL" ? 9.5 :
                getSeverity(obj) === "HIGH" ? 7.5 :
                getSeverity(obj) === "MEDIUM" ? 5.0 :
                getSeverity(obj) === "LOW" ? 2.0 : null
              ))}>{getSeverity(obj)}</span>
            )}
            {indicatorType && (
              <span style={S.badge(C.accent)}>indicator_type: {indicatorType}</span>
            )}
            {obj.source_count != null && (
              <span style={{ fontSize: 12, color: C.muted }}>{obj.source_count} source{obj.source_count > 1 ? "s" : ""}</span>
            )}
          </div>

          {/* Enrichment action */}
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {enrichment && enrichStatus !== "queued" ? (
              <button
                onClick={triggerEnrich}
                style={{ ...S.btn, color: C.muted, borderColor: C.border, fontSize: 12 }}
              >
                Déjà enrichi — ré-enrichir ?
              </button>
            ) : (
              <button
                onClick={triggerEnrich}
                disabled={enrichStatus === "queued"}
                style={{ ...S.btn, color: C.primary, borderColor: C.primary, fontSize: 12 }}
              >
                {enrichStatus === "queued" ? "Analyse en cours…" : "Enrichir"}
              </button>
            )}
            {enrichStatus === "done" && (
              <span style={{ fontSize: 12, color: C.green }}>✓ Résultats disponibles</span>
            )}
            {enrichStatus === "timeout" && (
              <span style={{ fontSize: 12, color: C.yellow }}>En attente de résultats (tâche en arrière-plan)</span>
            )}
            {enrichStatus === "error" && (
              <span style={{ fontSize: 12, color: C.red }}>Erreur lors de la mise en file</span>
            )}
          </div>

          {/* Enrichment results */}
          {enrichment && (
            <div style={{ ...S.card, background: C.bg }}>
              <div style={{ fontSize: 12, fontWeight: 500, color: C.muted, marginBottom: 10 }}>
                Enrichissement disponible
              </div>

              {vt && (
                <div style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 12, color: C.primary, marginBottom: 6, fontWeight: 500 }}>
                    VirusTotal
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4, fontSize: 12 }}>
                    {vt.malicious_count != null && (
                      <>
                        <span style={{ color: C.muted }}>Malicious</span>
                        <span style={{ color: vt.malicious_count > 0 ? C.red : C.green }}>
                          {vt.malicious_count}/{vt.total_engines}
                        </span>
                      </>
                    )}
                    {vt.reputation != null && (
                      <>
                        <span style={{ color: C.muted }}>Réputation</span>
                        <span>{vt.reputation}</span>
                      </>
                    )}
                    {vt.country && (
                      <>
                        <span style={{ color: C.muted }}>Pays</span>
                        <span>{vt.country}</span>
                      </>
                    )}
                    {vt.asn && (
                      <>
                        <span style={{ color: C.muted }}>ASN</span>
                        <span>{vt.asn}</span>
                      </>
                    )}
                  </div>
                </div>
              )}

              {shodan && (
                <div>
                  <div style={{ fontSize: 12, color: C.primary, marginBottom: 6, fontWeight: 500 }}>
                    Shodan
                  </div>
                  <div style={{ fontSize: 12 }}>
                    {shodan.ports?.length > 0 && (
                      <div style={{ marginBottom: 4 }}>
                        <span style={{ color: C.muted }}>Ports : </span>
                        {shodan.ports.join(", ")}
                      </div>
                    )}
                    {shodan.hostnames?.length > 0 && (
                      <div style={{ marginBottom: 4 }}>
                        <span style={{ color: C.muted }}>Hostnames : </span>
                        {shodan.hostnames.join(", ")}
                      </div>
                    )}
                    {shodan.vulns?.length > 0 && (
                      <div>
                        <span style={{ color: C.muted }}>CVEs : </span>
                        <span style={{ color: C.red }}>{shodan.vulns.join(", ")}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Full STIX JSON */}
          <div>
            <div style={{ fontSize: 12, color: C.muted, marginBottom: 6, fontWeight: 500 }}>
              STIX JSON
            </div>
            <pre style={{
              background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6,
              padding: 12, fontSize: 11, color: C.text, overflowX: "auto",
              whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0,
              maxHeight: 500, overflowY: "auto",
            }}>
              {JSON.stringify(obj.stix_data, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </>
  )
}

// ── TV View ───────────────────────────────────────────────────
const TV_REFRESH_SECONDS = 60

function useClock() {
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  return now
}

function useTvData(token) {
  const [data, setData] = useState({})
  const [countdown, setCountdown] = useState(TV_REFRESH_SECONDS)
  const countRef = useRef(TV_REFRESH_SECONDS)

  const refresh = useCallback(async () => {
    if (!token) return
    const h = { Authorization: `Bearer ${token}` }
    try {
      const [summary, incidents, alerts, cves] = await Promise.all([
        fetch(`${API}/metrics/summary`, { headers: h }).then(r => r.ok ? r.json() : null),
        fetch(`${API}/metrics/incidents`, { headers: h }).then(r => r.ok ? r.json() : null),
        fetch(`${API}/alerts?status=new&limit=10`, { headers: h }).then(r => r.ok ? r.json() : null),
        fetch(`${API}/metrics/recent-cves`, { headers: h }).then(r => r.ok ? r.json() : null),
      ])
      setData({ summary, incidents, alerts, cves })
    } catch { /* keep previous */ }
    countRef.current = TV_REFRESH_SECONDS
  }, [token])

  useEffect(() => { refresh() }, [refresh])

  useEffect(() => {
    const t = setInterval(() => {
      countRef.current -= 1
      setCountdown(countRef.current)
      if (countRef.current <= 0) refresh()
    }, 1000)
    return () => clearInterval(t)
  }, [refresh])

  return { data, countdown, refresh }
}

function TVView({ token }) {
  const now = useClock()
  const { data, countdown, refresh } = useTvData(token)
  const { summary, incidents, alerts, cves } = data

  const live = incidents?.source === "grafana"

  const incidentPill = (label, value, color) => (
    <div style={{
      flex: 1, display: "flex", flexDirection: "column", alignItems: "center",
      padding: "20px 0", borderRadius: 10,
      background: live ? color + "18" : C.surface,
      border: `2px solid ${live ? color + "55" : C.border}`,
    }}>
      <span style={{ fontSize: 56, fontWeight: 800, color: live ? color : C.muted, lineHeight: 1 }}>
        {live ? (value ?? "0") : "—"}
      </span>
      <span style={{ fontSize: 13, color: C.muted, marginTop: 8, textTransform: "uppercase", letterSpacing: "0.1em" }}>
        {label}
      </span>
    </div>
  )

  const kpi = (label, value, color = C.text) => (
    <div style={{
      flex: 1, textAlign: "center", background: C.surface,
      border: `1px solid ${C.border}`, borderRadius: 8, padding: "14px 8px",
    }}>
      <div style={{ fontSize: 30, fontWeight: 700, color, lineHeight: 1 }}>{value ?? "—"}</div>
      <div style={{ fontSize: 11, color: C.muted, marginTop: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>{label}</div>
    </div>
  )

  const severityDot = (sev) => {
    const color = SEVERITY_COLORS[sev] || C.muted
    return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: color, marginRight: 6, flexShrink: 0 }} />
  }

  return (
    <div style={{
      background: C.bg, color: C.text, minHeight: "100vh", width: "100vw",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      display: "flex", flexDirection: "column", boxSizing: "border-box", padding: "18px 24px", gap: 16,
    }}>

      {/* ── Header ── */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
          <span style={{ fontSize: 13, color: C.muted }}>
            Refresh in <span style={{ color: countdown <= 10 ? C.yellow : C.muted }}>{countdown}s</span>
          </span>
          <button onClick={refresh} style={{ ...S.btn, fontSize: 12, padding: "4px 10px", color: C.muted }}>
            ↺ Now
          </button>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 28, fontWeight: 700, fontVariantNumeric: "tabular-nums", letterSpacing: "0.02em" }}>
              {now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
            </div>
            <div style={{ fontSize: 12, color: C.muted, marginTop: 1 }}>
              {now.toLocaleDateString([], { weekday: "long", day: "numeric", month: "long", year: "numeric" })}
            </div>
          </div>
        </div>
      </div>

      {/* ── Incident pills ── */}
      <div style={{ display: "flex", gap: 14 }}>
        {incidentPill("New", incidents?.new, C.red)}
        {incidentPill("Acknowledged", incidents?.acknowledged, C.yellow)}
        {incidentPill("Resolved", incidents?.resolved, C.green)}
      </div>

      {/* ── KPI row ── */}
      <div style={{ display: "flex", gap: 12 }}>
        {kpi("Total objects", summary?.total_objects?.toLocaleString())}
        {kpi("Last 24 h", summary?.objects_last_24h?.toLocaleString(), C.primary)}
        {kpi("Open alerts", summary?.alerts_new, summary?.alerts_new > 0 ? C.red : C.green)}
        {kpi("Active sources", summary?.active_sources)}
      </div>

      {/* ── Main grid ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, flex: 1, minHeight: 0 }}>

        {/* Open alerts */}
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "10px 16px", borderBottom: `1px solid ${C.border}`, fontSize: 13, fontWeight: 600, color: C.text, display: "flex", justifyContent: "space-between" }}>
            <span>Open alerts</span>
            <span style={{ fontSize: 12, color: C.muted }}>{alerts?.items?.length ?? 0} shown</span>
          </div>
          <div style={{ overflowY: "auto", flex: 1 }}>
            {(alerts?.items || []).length === 0
              ? <div style={{ padding: 20, fontSize: 13, color: C.green, textAlign: "center" }}>✓ No open alerts</div>
              : (alerts?.items || []).map(a => (
                <div key={a.id} style={{ padding: "10px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 10 }}>
                  {severityDot(a.severity)}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {a.perimeter_name}
                    </div>
                    <div style={{ fontSize: 11, color: C.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "monospace" }}>
                      {a.stix_id || a.stix_object_id || ""}
                    </div>
                  </div>
                  <div style={{ textAlign: "right", flexShrink: 0 }}>
                    <SeverityBadge severity={a.severity} />
                    <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>
                      {new Date(a.triggered_at).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}
                    </div>
                  </div>
                </div>
              ))
            }
          </div>
        </div>

        {/* Recent CVEs */}
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "10px 16px", borderBottom: `1px solid ${C.border}`, fontSize: 13, fontWeight: 600, color: C.text }}>
            Recent CVEs
          </div>
          <div style={{ overflowY: "auto", flex: 1 }}>
            {(cves || []).length === 0
              ? <div style={{ padding: 20, fontSize: 13, color: C.muted, textAlign: "center" }}>No CVEs yet</div>
              : (cves || []).map(c => (
                <div key={c.stix_id} style={{ padding: "10px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 12 }}>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
                    <span style={S.badge(cvssColor(c.cvss_score))}>{c.cve_id}</span>
                    {c.cvss_score != null && (
                      <span style={{ fontSize: 11, fontWeight: 700, color: cvssColor(c.cvss_score) }}>{c.cvss_score.toFixed(1)}</span>
                    )}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    {c.description
                      ? <div style={{ fontSize: 12, color: C.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.description}</div>
                      : <div style={{ fontSize: 12, color: C.border }}>No description</div>
                    }
                    <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>
                      {new Date(c.created_at).toLocaleDateString()}
                    </div>
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 700, flexShrink: 0, color: c.confidence >= 70 ? C.green : c.confidence >= 40 ? C.yellow : C.red }}>
                    {c.confidence}
                  </span>
                </div>
              ))
            }
          </div>
        </div>

      </div>
    </div>
  )
}

// ── Settings ──────────────────────────────────────────────────
function SettingsView({ token }) {
  const [prompt, setPrompt] = useState("")
  const [isDefault, setIsDefault] = useState(true)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [status, setStatus] = useState(null) // null | "saved" | "reset" | "error"

  const loadPrompt = useCallback(async () => {
    setLoading(true)
    try {
      const r = await fetch(`${API}/settings/llm-prompt`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) {
        const data = await r.json()
        setPrompt(data.prompt)
        setIsDefault(data.is_default)
      }
    } catch { /* ignore */ }
    setLoading(false)
  }, [token])

  useEffect(() => { loadPrompt() }, [loadPrompt])

  const savePrompt = async () => {
    setSaving(true)
    setStatus(null)
    try {
      const r = await fetch(`${API}/settings/llm-prompt`, {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
      })
      if (r.ok) {
        const data = await r.json()
        setIsDefault(data.is_default)
        setStatus("saved")
      } else { setStatus("error") }
    } catch { setStatus("error") }
    setSaving(false)
  }

  const resetPrompt = async () => {
    setSaving(true)
    setStatus(null)
    try {
      const r = await fetch(`${API}/settings/llm-prompt`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) {
        const data = await r.json()
        setPrompt(data.prompt)
        setIsDefault(data.is_default)
        setStatus("reset")
      } else { setStatus("error") }
    } catch { setStatus("error") }
    setSaving(false)
  }

  if (loading) return <Spinner />

  return (
    <div style={{ padding: 24 }}>
      <div style={{ ...S.card }}>
        <div style={{ fontSize: 14, fontWeight: 500, marginBottom: 12 }}>LLM System Prompt</div>
        <div style={{ fontSize: 12, color: C.muted, marginBottom: 12 }}>
          Ce prompt est envoyé au LLM à chaque inférence pour guider l'extraction STIX.
          {isDefault && <span style={{ marginLeft: 8, color: C.green }}>(défaut)</span>}
          {!isDefault && <span style={{ marginLeft: 8, color: C.yellow }}>(personnalisé)</span>}
        </div>
        <textarea
          value={prompt}
          onChange={e => { setPrompt(e.target.value); setStatus(null) }}
          style={{
            width: "100%", minHeight: 400, resize: "vertical",
            ...S.btn, background: C.bg, color: C.text, boxSizing: "border-box",
            fontFamily: "monospace", fontSize: 12, lineHeight: 1.5,
            whiteSpace: "pre-wrap",
          }}
        />
        <div style={{ marginTop: 14, display: "flex", gap: 8, alignItems: "center" }}>
          <button
            style={{ ...S.btn, color: C.primary, borderColor: C.primary }}
            onClick={savePrompt}
            disabled={saving}
          >
            {saving ? "Enregistrement…" : "Enregistrer"}
          </button>
          <button
            style={{ ...S.btn, color: C.muted }}
            onClick={resetPrompt}
            disabled={saving || isDefault}
          >
            Reset to default
          </button>
          {status === "saved" && <span style={{ fontSize: 12, color: C.green }}>Prompt enregistré</span>}
          {status === "reset" && <span style={{ fontSize: 12, color: C.green }}>Prompt réinitialisé</span>}
          {status === "error" && <span style={{ fontSize: 12, color: C.red }}>Erreur</span>}
        </div>
      </div>
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
const VIEWS = ["Overview", "Objects", "Alerts", "Perimeters", "Sources", "Metrics", "Settings"]

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem("cti_token") || "")
  const [view, setView] = useState("Overview")
  const isTv = new URLSearchParams(window.location.search).get("tv") === "1"

  const login = (t) => { sessionStorage.setItem("cti_token", t); setToken(t) }
  const logout = () => { sessionStorage.removeItem("cti_token"); setToken("") }

  if (!token) return <Login onLogin={login} />

  // TV mode: fullscreen, no chrome
  if (isTv) return <TVView token={token} />

  const ViewComponent = {
    Overview, Objects: ObjectsView, Alerts: AlertsView,
    Perimeters: PerimetersView, Sources: SourcesView, Metrics: MetricsView,
    Settings: SettingsView,
  }[view]

  const openTv = () => window.open("/?tv=1", "_blank", "noopener")

  return (
    <div style={{ display: "flex", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", fontSize: 14, color: C.text }}>
      <div style={S.sidebar}>
        <div style={{ padding: "14px 16px", borderBottom: `1px solid ${C.border}`, fontSize: 14, fontWeight: 600, color: C.text }}>
          CTI Aggregator
        </div>
        <nav style={{ flex: 1, padding: "8px 8px" }}>
          {VIEWS.map(v => <NavItem key={v} label={v} active={view === v} onClick={() => setView(v)} />)}
        </nav>
        <div style={{ padding: "12px 16px", borderTop: `1px solid ${C.border}`, display: "flex", flexDirection: "column", gap: 8 }}>
          <button style={{ ...S.btn, width: "100%", color: C.primary, fontSize: 12 }} onClick={openTv}>
            ⊞ TV View
          </button>
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
