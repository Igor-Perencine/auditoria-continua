import React from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, Stat, STATUS_LABEL, SEV_LABEL, fmtDate, go, useAction, useApi } from "../ui.jsx";

const ORDER = ["conforme", "nao_conforme", "impossivel_avaliar", "documentado", "manual", "sem_evidencia", "nao_avaliado"];

function StackBar({ counts, total }) {
  return (
    <div className="stackbar">
      {ORDER.filter((s) => counts[s]).map((s) => (
        <div key={s} className={`seg st-${s}`} style={{ width: `${(100 * counts[s]) / total}%` }} title={`${STATUS_LABEL[s]}: ${counts[s]}`}>
          {counts[s]}
        </div>
      ))}
    </div>
  );
}

export default function Dashboard({ user }) {
  const { data, error, loading, reload } = useApi("/dashboard");
  const act = useAction();

  const runNow = async () => {
    const r = await act.run(() => api("/runs", { method: "POST" }));
    if (r) {
      act.setMsg(r.started ? "Ciclo de auditoria iniciado. Atualize em alguns segundos." : r.message);
      setTimeout(reload, 4000);
    }
  };

  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox error={error} />;
  const d = data;

  return (
    <div>
      <div className="page-head">
        <h1>Painel de auditoria contínua</h1>
        <div className="actions">
          <button className="btn" onClick={reload}>Atualizar</button>
          {["auditor", "admin"].includes(user.role) && (
            <button className="btn primary" disabled={act.busy} onClick={runNow}>Executar ciclo agora</button>
          )}
        </div>
      </div>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />

      <div className="stats">
        <Stat label="Conformidade (controles avaliados)" value={d.conformity_pct !== null ? `${d.conformity_pct}%` : "—"} tone="blue" />
        <Stat label="Achados abertos" value={d.open_findings} tone="red" />
        <Stat label="Aguardando decisão do auditor" value={d.pending_review} hint={`${d.mandatory_review} com revisão obrigatória`} tone="amber" />
        <Stat label="Controles mapeados" value={d.total_controls} hint={`${(d.automation_counts.automatizavel || 0) + (d.automation_counts.parcial || 0)} com automação total ou parcial`} />
      </div>

      <div className="grid2">
        <section className="card">
          <h2>Status dos 93 controles por tema</h2>
          {d.by_theme.map((t) => {
            const total = Object.values(t.counts).reduce((a, b) => a + b, 0);
            return (
              <div key={t.theme} className="theme-row">
                <div className="theme-name">{t.theme} <span className="muted">({total})</span></div>
                <StackBar counts={t.counts} total={total} />
              </div>
            );
          })}
          <div className="legend">
            {ORDER.map((s) => (
              <span key={s}><i className={`dot st-${s}`} /> {STATUS_LABEL[s]}</span>
            ))}
          </div>
        </section>

        <section className="card">
          <h2>Achados abertos por severidade</h2>
          {["critica", "alta", "media", "baixa"].map((s) => {
            const v = d.open_by_severity[s] || 0;
            const max = Math.max(1, ...Object.values(d.open_by_severity));
            return (
              <div key={s} className="bar-row" onClick={() => go("achados")}>
                <span className="bar-label">{SEV_LABEL[s]}</span>
                <div className="bar"><div className={`bar-fill sev-${s}`} style={{ width: `${(100 * v) / max}%` }} /></div>
                <span className="bar-val">{v}</span>
              </div>
            );
          })}
          <h2 style={{ marginTop: 24 }}>Inteligência artificial</h2>
          <p className="small">
            Provedor: <strong>{d.ai.provider}</strong> {d.ai.enabled ? `· ${d.ai.model}` : "(desabilitada — apenas regras determinísticas)"}
            <br />Pseudonimização antes do envio: <strong>{d.ai.pseudonymize ? "ativa" : "desativada"}</strong>
          </p>
        </section>
      </div>

      <section className="card">
        <h2>Últimas execuções</h2>
        <table>
          <thead><tr><th>#</th><th>Gatilho</th><th>Início</th><th>Status</th><th>Evidências</th><th>Novos achados</th><th>Encerrados</th></tr></thead>
          <tbody>
            {d.last_runs.map((r) => (
              <tr key={r.id}>
                <td>{r.id}</td><td>{r.trigger}</td><td>{fmtDate(r.started_at)}</td><td>{r.status}</td>
                <td>{r.evidence_count}</td><td>{r.findings_new}</td><td>{r.findings_resolved}</td>
              </tr>
            ))}
            {!d.last_runs.length && <tr><td colSpan="7" className="muted">Nenhuma execução ainda — o primeiro ciclo roda cerca de 20 s após a inicialização.</td></tr>}
          </tbody>
        </table>
      </section>
    </div>
  );
}
