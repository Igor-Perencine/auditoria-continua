import React, { useState } from "react";
import { api } from "../api.js";
import { AUTO_LABEL, ErrorBox, Loading, Stat, fmtDate, fmtDuration, useAction, useApi } from "../ui.jsx";

function kappaLabel(k) {
  if (k === null || k === undefined) return "";
  if (k < 0) return "pior que o acaso";
  if (k <= 0.2) return "leve";
  if (k <= 0.4) return "razoável";
  if (k <= 0.6) return "moderada";
  if (k <= 0.8) return "substancial";
  return "quase perfeita";
}

export default function Metrics({ user }) {
  const { data, error, loading, reload } = useApi("/metrics");
  const act = useAction();
  const [repro, setRepro] = useState(null);

  const runRepro = async () => {
    const r = await act.run(() => api("/metrics/reproducibility", { method: "POST" }));
    if (r) setRepro(r);
  };

  const exportJson = () => {
    const blob = new Blob([JSON.stringify({ metrics: data, reproducibility: repro }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `metricas-auditoria-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
  };

  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox error={error} />;
  const m = data;
  const k = m.ai_agreement;

  return (
    <div>
      <div className="page-head">
        <h1>Métricas da pesquisa</h1>
        <div className="actions">
          <button className="btn" onClick={reload}>Atualizar</button>
          <button className="btn" onClick={exportJson}>Exportar JSON</button>
        </div>
      </div>
      <p className="muted small">Indicadores definidos no TCC: cobertura, tempo de detecção, reprodutibilidade, falsos positivos e concordância entre a sugestão da IA e a decisão do auditor.</p>
      <ErrorBox error={act.error} />

      <h2>Cobertura</h2>
      <div className="stats">
        <Stat label="Controles com automação total ou parcial" value={`${m.coverage.automatable_pct}%`} hint={Object.entries(m.coverage.by_automation).map(([a, n]) => `${AUTO_LABEL[a]}: ${n}`).join(" · ")} tone="blue" />
        <Stat label="Controles avaliados automaticamente agora" value={`${m.coverage.evaluated_automatically} / ${m.coverage.total_controls}`} hint={`${m.coverage.evaluated_pct}%`} />
        <Stat label="Ciclos executados" value={m.runs} />
      </div>

      <h2>Tempo de detecção (cenários controlados)</h2>
      <div className="stats">
        <Stat label="Média" value={fmtDuration(m.detection.avg_seconds)} tone="green" />
        <Stat label="Máximo" value={fmtDuration(m.detection.max_seconds)} />
        <Stat label="Cenários detectados" value={m.detection.count} />
      </div>
      {m.detection.items.length > 0 && (
        <div className="card nopad">
          <table>
            <thead><tr><th>Cenário</th><th>Injetado</th><th>Detectado</th><th>Tempo</th></tr></thead>
            <tbody>
              {m.detection.items.map((d, i) => (
                <tr key={i}><td>{d.title || d.scenario}</td><td className="tiny">{fmtDate(d.injected_at)}</td><td className="tiny">{fmtDate(d.detected_at)}</td><td>{fmtDuration(d.seconds)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Revisão humana e IA</h2>
      <div className="stats">
        <Stat label="Decisões do auditor" value={m.human_review.decisions} />
        <Stat label="Taxa de falsos positivos" value={m.human_review.false_positive_rate !== null ? `${(m.human_review.false_positive_rate * 100).toFixed(1)}%` : "—"} hint={`${m.human_review.false_positives} rejeitados`} tone="amber" />
        <Stat label="Tempo médio até a decisão" value={fmtDuration(m.human_review.avg_seconds_to_decision)} />
        <Stat label="Concordância IA × auditor (Kappa de Cohen)" value={k.kappa ?? "—"} hint={k.n ? `${kappaLabel(k.kappa)} · acordo bruto ${(k.agreement * 100).toFixed(0)}% · n=${k.n}` : "sem decisões com sugestão da IA"} tone="blue" />
      </div>
      {k.matrix && (
        <div className="card">
          <h3>Matriz de confusão (IA × auditor)</h3>
          <table className="matrix">
            <thead><tr><th></th><th>Auditor: não conforme</th><th>Auditor: não (FP / outro)</th></tr></thead>
            <tbody>
              <tr><th>IA: não conforme</th><td>{k.matrix.ia_nc_auditor_nc}</td><td>{k.matrix.ia_nc_auditor_nao}</td></tr>
              <tr><th>IA: não (FP / outro)</th><td>{k.matrix.ia_nao_auditor_nc}</td><td>{k.matrix.ia_nao_auditor_nao}</td></tr>
            </tbody>
          </table>
        </div>
      )}

      <h2>Correção</h2>
      <div className="stats">
        <Stat label="Achados encerrados por reexecução" value={m.remediation.resolved} />
        <Stat label="Tempo médio até a correção" value={fmtDuration(m.remediation.avg_seconds_to_resolution)} />
        <Stat label="Controles com mais achados" value={m.remediation.top_controls.map(([c, n]) => `${c} (${n})`).join(", ") || "—"} />
      </div>

      <h2>Reprodutibilidade</h2>
      <div className="card">
        <p className="small">Reexecuta as regras sobre as evidências gravadas (descriptografadas) da última execução e compara com os achados registrados.</p>
        {["auditor", "admin"].includes(user.role) && <button className="btn" onClick={runRepro} disabled={act.busy}>Executar teste de reprodutibilidade</button>}
        {repro && (
          <div className={`chain ${repro.ok ? "ok" : "bad"}`}>
            <strong>{repro.ok ? "Resultados idênticos ✓" : "Divergências encontradas"}</strong>
            <div className="small">
              Execução #{repro.run_id} · {repro.evidence} evidências · recalculados {repro.recomputed} · registrados {repro.recorded} · Jaccard {repro.jaccard}
            </div>
            {!repro.ok && <div className="tiny">{repro.note}<br />Só recalculados: {repro.only_recomputed.join(", ") || "—"}<br />Só registrados: {repro.only_recorded.join(", ") || "—"}</div>}
          </div>
        )}
      </div>
    </div>
  );
}
