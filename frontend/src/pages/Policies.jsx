import React, { useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, fmtDate, useAction, useApi } from "../ui.jsx";

export default function Policies({ user }) {
  const { data, error, loading, reload } = useApi("/policies");
  const act = useAction();
  const [file, setFile] = useState(null);
  const [form, setForm] = useState({ title: "", code: "", version: "1.0", approved_at: "", controls: "" });
  const [q, setQ] = useState("");
  const [results, setResults] = useState(null);
  const canUpload = ["admin", "auditor"].includes(user.role);

  const upload = async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append("file", file);
    Object.entries(form).forEach(([k, v]) => fd.append(k, v));
    const r = await act.run(() => api("/policies", { method: "POST", form: fd }), "Política carregada e indexada.");
    if (r) {
      setFile(null);
      e.target.reset();
      setForm({ title: "", code: "", version: "1.0", approved_at: "", controls: "" });
      reload();
    }
  };
  const search = async (e) => {
    e.preventDefault();
    const r = await act.run(() => api(`/policies/search?q=${encodeURIComponent(q)}`));
    if (r) setResults(r);
  };
  const remove = async (d) => {
    if (!window.confirm(`Remover a política ${d.code}?`)) return;
    if (await act.run(() => api(`/policies/${d.id}`, { method: "DELETE" }), "Política removida.")) reload();
  };
  const reindex = async () => {
    const r = await act.run(() => api("/policies/reindex", { method: "POST" }));
    if (r) { act.setMsg(`${r.embedded} trechos indexados.`); reload(); }
  };
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  return (
    <div>
      <div className="page-head">
        <h1>Base de políticas internas</h1>
        {user.role === "admin" && <button className="btn" onClick={reindex} disabled={act.busy}>Gerar embeddings pendentes</button>}
      </div>
      <p className="muted small">
        Fonte autorizada do RAG: a IA só pode fundamentar suas sugestões nestes documentos. Cada documento é dividido em trechos,
        vinculado aos controles (por citação explícita "A.x.y", palavras-chave ou indicação manual) e convertido em vetores (pgvector).
      </p>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />

      <div className="grid2">
        {canUpload && (
          <section className="card">
            <h2>Carregar política</h2>
            <form onSubmit={upload}>
              <label>Arquivo (PDF, DOCX, TXT ou MD — até 10 MB)</label>
              <input type="file" accept=".pdf,.docx,.txt,.md" onChange={(e) => setFile(e.target.files[0])} />
              <div className="row">
                <div><label>Código</label><input value={form.code} onChange={set("code")} placeholder="POL-SI-006" /></div>
                <div><label>Versão</label><input value={form.version} onChange={set("version")} /></div>
                <div><label>Aprovada em</label><input type="date" value={form.approved_at} onChange={set("approved_at")} /></div>
              </div>
              <label>Título</label>
              <input value={form.title} onChange={set("title")} />
              <label>Controles cobertos (opcional, separados por vírgula)</label>
              <input value={form.controls} onChange={set("controls")} placeholder="A.5.15, A.8.2" />
              <button className="btn primary" disabled={!file || act.busy}>{act.busy ? "Processando…" : "Carregar"}</button>
            </form>
          </section>
        )}
        <section className="card">
          <h2>Testar recuperação (RAG)</h2>
          <form onSubmit={search} className="filters">
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="ex.: prazo para corrigir vulnerabilidade crítica" style={{ flex: 1 }} />
            <button className="btn" disabled={!q || act.busy}>Buscar</button>
          </form>
          {results && (results.length ? results.map((r) => (
            <blockquote key={r.chunk_id}><div className="tiny muted">{r.code} — {r.document} · controles: {r.controls.join(", ") || "—"}</div>{r.text}</blockquote>
          )) : <p className="muted small">Nada encontrado.</p>)}
        </section>
      </div>

      {loading && !data ? <Loading /> : <ErrorBox error={error} />}
      {data && (
        <div className="card nopad">
          <table>
            <thead><tr><th>Código</th><th>Título</th><th>Versão</th><th>Aprovada em</th><th>Trechos</th><th>Controles vinculados</th><th>Embeddings</th><th>SHA-256</th><th></th></tr></thead>
            <tbody>
              {data.map((d) => (
                <tr key={d.id}>
                  <td><strong>{d.code}</strong></td>
                  <td>{d.title}</td>
                  <td>{d.version}</td>
                  <td className={d.age_days > 365 ? "warn" : ""}>{d.approved_at || "—"}{d.age_days > 365 && <div className="tiny">revisão vencida</div>}</td>
                  <td>{d.n_chunks}</td>
                  <td className="wrap tiny">{d.controls.join(", ")}</td>
                  <td>{d.embedded ? "✓" : <span className="muted">—</span>}</td>
                  <td className="tiny mono">{d.sha256.slice(0, 12)}…</td>
                  <td>{user.role === "admin" && <button className="btn small ghost" onClick={() => remove(d)}>Remover</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="tiny muted pad">Carregado em: {data[0] ? fmtDate(data[0].uploaded_at) : "—"}</p>
        </div>
      )}
    </div>
  );
}
