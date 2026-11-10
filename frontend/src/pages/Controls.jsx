import React, { useState } from "react";
import { AUTO_LABEL, ErrorBox, Loading, SevBadge, StatusBadge, fmtDate, go, useApi } from "../ui.jsx";

function ControlRow({ c }) {
  const [open, setOpen] = useState(false);
  const { data } = useApi(open ? `/controls/${c.id}` : null);
  return (
    <>
      <tr onClick={() => setOpen(!open)}>
        <td><strong>{c.id}</strong></td>
        <td className="wrap">{c.title}</td>
        <td>{c.theme}</td>
        <td><span className={`badge auto-${c.automation}`}>{AUTO_LABEL[c.automation]}</span></td>
        <td><StatusBadge value={c.status} /></td>
        <td>{c.open_findings || ""}</td>
        <td className="tiny">{c.evaluated_at ? fmtDate(c.evaluated_at) : "—"}</td>
      </tr>
      {open && (
        <tr className="expanded">
          <td colSpan="7">
            {!data ? <Loading /> : (
              <div className="grid2">
                <div>
                  <h3>Testes automatizados</h3>
                  {data.rules.length ? data.rules.map((r) => (
                    <div key={r.rule_id} className="small"><strong>{r.rule_id}</strong> — {r.title}<div className="muted tiny">{r.criterion}</div></div>
                  )) : <p className="muted small">Sem regra automatizada. Frequência sugerida: {c.frequency}.</p>}
                  <h3>Achados abertos</h3>
                  {data.open_findings.length ? data.open_findings.map((f) => (
                    <div key={f.id} className="small link" onClick={() => go(`achados/${f.id}`)}>
                      #{f.id} <SevBadge value={f.severity} /> {f.asset}: {f.condition}
                    </div>
                  )) : <p className="muted small">Nenhum.</p>}
                </div>
                <div>
                  <h3>Trechos de política vinculados</h3>
                  {data.policies.length ? data.policies.map((p) => (
                    <blockquote key={p.chunk_id}><div className="tiny muted">{p.code} — {p.document}</div>{p.text}</blockquote>
                  )) : <p className="muted small">Nenhuma política vinculada a este controle.</p>}
                </div>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

export default function Controls() {
  const { data, error, loading } = useApi("/controls");
  const [theme, setTheme] = useState("");
  const [auto, setAuto] = useState("");
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox error={error} />;
  const items = data.filter((c) =>
    (!theme || c.theme === theme) && (!auto || c.automation === auto) && (!status || c.status === status) &&
    (!q || `${c.id} ${c.title}`.toLowerCase().includes(q.toLowerCase())));

  return (
    <div>
      <div className="page-head"><h1>Controles do Anexo A (ISO/IEC 27001:2022)</h1></div>
      <p className="muted small">
        Mapeamento dos 93 controles quanto ao potencial de verificação automatizada (objetivo específico "a"). Clique em um controle para ver testes, achados e políticas vinculadas.
      </p>
      <div className="filters">
        <input placeholder="Buscar…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={theme} onChange={(e) => setTheme(e.target.value)}>
          <option value="">Todos os temas</option>
          {["Organizacional", "Pessoas", "Físico", "Tecnológico"].map((t) => <option key={t}>{t}</option>)}
        </select>
        <select value={auto} onChange={(e) => setAuto(e.target.value)}>
          <option value="">Toda automação</option>
          {Object.entries(AUTO_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Todos os status</option>
          {["conforme", "nao_conforme", "impossivel_avaliar", "documentado", "manual", "sem_evidencia", "nao_avaliado"].map((s) => (
            <option key={s} value={s}>{s.replace("_", " ")}</option>
          ))}
        </select>
        <span className="muted small">{items.length} controles</span>
      </div>
      <div className="card nopad">
        <table className="clickable">
          <thead><tr><th>ID</th><th>Controle</th><th>Tema</th><th>Automação</th><th>Status</th><th>Achados</th><th>Avaliado em</th></tr></thead>
          <tbody>{items.map((c) => <ControlRow key={c.id} c={c} />)}</tbody>
        </table>
      </div>
    </div>
  );
}
