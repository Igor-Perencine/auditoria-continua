import React, { useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, REVIEW_LABEL, SevBadge, StatusBadge, fmtDate, go, useAction, useApi } from "../ui.jsx";

export default function Findings({ user }) {
  const [open, setOpen] = useState(true);
  const [review, setReview] = useState("pendente");
  const [severity, setSeverity] = useState("");
  const qs = new URLSearchParams({ open: String(open) });
  if (review) qs.set("review_state", review);
  if (severity) qs.set("severity", severity);
  const { data, error, loading, reload } = useApi(`/findings?${qs}`);
  const act = useAction();

  const classifyAll = async () => {
    const r = await act.run(() => api("/ai/classify-pending", { method: "POST" }), "Triagem por IA iniciada em segundo plano.");
    if (r) setTimeout(reload, 8000);
  };

  return (
    <div>
      <div className="page-head">
        <h1>Triagem de achados</h1>
        <div className="actions">
          <button className="btn" onClick={reload}>Atualizar</button>
          {["auditor", "admin"].includes(user.role) && (
            <button className="btn" disabled={act.busy} onClick={classifyAll}>Pré-classificar pendentes com IA</button>
          )}
        </div>
      </div>
      <p className="muted small">
        Ordenados por prioridade: revisão obrigatória (alto impacto, baixa confiança da IA ou exceção não documentada) → severidade → antiguidade.
        A IA apenas sugere; a decisão final é do auditor.
      </p>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />

      <div className="filters">
        <select value={String(open)} onChange={(e) => setOpen(e.target.value === "true")}>
          <option value="true">Abertos</option>
          <option value="false">Encerrados</option>
        </select>
        <select value={review} onChange={(e) => setReview(e.target.value)}>
          <option value="">Todas as revisões</option>
          <option value="pendente">Pendentes</option>
          <option value="confirmado">Confirmados</option>
          <option value="falso_positivo">Falsos positivos</option>
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">Todas as severidades</option>
          <option value="critica">Crítica</option>
          <option value="alta">Alta</option>
          <option value="media">Média</option>
          <option value="baixa">Baixa</option>
        </select>
      </div>

      {loading && !data ? <Loading /> : <ErrorBox error={error} />}
      {data && (
        <div className="card nopad">
          <table className="clickable">
            <thead>
              <tr><th>#</th><th>Controle</th><th>Ativo</th><th>Condição observada</th><th>Severidade</th><th>Resultado</th><th>IA sugere</th><th>Revisão</th><th>Detectado</th></tr>
            </thead>
            <tbody>
              {data.map((f) => (
                <tr key={f.id} onClick={() => go(`achados/${f.id}`)}>
                  <td>{f.id}</td>
                  <td><strong>{f.control_id}</strong><div className="tiny muted">{f.control_title}</div></td>
                  <td>{f.asset}</td>
                  <td className="wrap">
                    {f.condition}
                    {f.requires_human_review && f.review_state === "pendente" && (
                      <div className="tiny warn">⚠ Revisão obrigatória: {f.review_reasons.join(", ")}</div>
                    )}
                  </td>
                  <td><SevBadge value={f.severity} /></td>
                  <td><StatusBadge value={f.status} /></td>
                  <td>
                    {f.ai_status_suggested ? (
                      <>
                        <StatusBadge value={f.ai_status_suggested} />
                        <div className="tiny muted">confiança {Math.round((f.ai_confidence || 0) * 100)}%</div>
                      </>
                    ) : <span className="muted tiny">—</span>}
                  </td>
                  <td>{REVIEW_LABEL[f.review_state]}</td>
                  <td className="tiny">{fmtDate(f.first_detected_at)}</td>
                </tr>
              ))}
              {!data.length && <tr><td colSpan="9" className="muted">Nenhum achado com esses filtros.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
