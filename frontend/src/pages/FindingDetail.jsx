import React, { useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, REVIEW_LABEL, SEV_LABEL, SevBadge, StatusBadge, fmtDate, go, useAction, useApi } from "../ui.jsx";

export default function FindingDetail({ id, user }) {
  const { data: f, error, loading, reload } = useApi(`/findings/${id}`);
  const act = useAction();
  const [note, setNote] = useState("");
  const [sev, setSev] = useState("");
  const [status, setStatus] = useState("");
  const [evidence, setEvidence] = useState(null);

  if (loading && !f) return <Loading />;
  if (error) return <ErrorBox error={error} />;

  const decide = async (action) => {
    const body = { action, note };
    if (action === "alterar") {
      if (sev) body.severity = sev;
      if (status) body.status = status;
    }
    const r = await act.run(() => api(`/findings/${id}/decision`, { method: "POST", body }), "Decisão registrada.");
    if (r) {
      setNote("");
      reload();
    }
  };
  const reclassify = async () => {
    const r = await act.run(() => api(`/findings/${id}/classify`, { method: "POST" }), "Achado reclassificado pela IA.");
    if (r) reload();
  };
  const showEvidence = async () => {
    const r = await act.run(() => api(`/evidence/${f.evidence.id}`));
    if (r) setEvidence(r);
  };

  const ai = f.ai;
  return (
    <div>
      <div className="page-head">
        <div>
          <a href="#/achados" className="small">← Voltar à triagem</a>
          <h1>Achado #{f.id} · {f.control_id} — {f.control_title}</h1>
        </div>
        <div className="actions">
          <SevBadge value={f.severity} /> <StatusBadge value={f.status} />
          <span className="badge">{f.is_open ? "Aberto" : "Encerrado"}</span>
          <span className="badge">{REVIEW_LABEL[f.review_state]}</span>
        </div>
      </div>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />

      {/* Cadeia de rastreabilidade: critério -> regra -> evidência -> resultado -> decisão */}
      <div className="trace">
        <div className="trace-step"><div className="trace-k">1. Critério</div><div>{f.criterion}</div><div className="tiny muted">Regra {f.rule_id} · versão {f.rule_version}</div></div>
        <div className="trace-step"><div className="trace-k">2. Evidência</div><div>{f.evidence.source}</div><div className="tiny muted">#{f.evidence.seq} · {fmtDate(f.evidence.collected_at)}<br />SHA-256 {f.evidence.hash.slice(0, 16)}…</div></div>
        <div className="trace-step"><div className="trace-k">3. Condição observada</div><div>{f.condition}</div><div className="tiny muted">Ativo {f.asset} ({f.asset_type}, criticidade {f.asset_criticality}/5) · responsável: {f.asset_owner || "—"}</div></div>
        <div className="trace-step"><div className="trace-k">4. Resultado</div><div><StatusBadge value={f.status} /> severidade calculada <SevBadge value={f.calculated_severity} /></div><div className="tiny muted">Base {SEV_LABEL[f.base_severity]} × criticidade do ativo · {f.occurrences} ocorrência(s)</div></div>
      </div>

      <div className="grid2">
        <section className="card">
          <h2>Pré-classificação da IA (RAG)</h2>
          {ai.classified_at ? (
            <>
              <p>
                Sugestão: <StatusBadge value={ai.status_suggested} /> · severidade <SevBadge value={ai.severity} /> · confiança{" "}
                <strong>{Math.round(ai.confidence * 100)}%</strong>
              </p>
              <p className="justif">{ai.justification}</p>
              <h3>Trechos de política citados</h3>
              {ai.citations_valid === false && <div className="warn small">⚠ A IA citou trechos que não estavam entre os recuperados — possível alucinação.</div>}
              {ai.citations.length ? ai.citations.map((c) => (
                <blockquote key={c.ref}>
                  <div className="tiny muted">[{c.ref}] {c.code} — {c.document} (v{c.version})</div>
                  {c.excerpt}
                </blockquote>
              )) : <p className="muted small">Nenhum trecho citado (nenhuma política sustenta ou excetua o achado).</p>}
              <p className="tiny muted">Modelo {ai.model} · {fmtDate(ai.classified_at)} · hash do prompt enviado (pseudonimizado): {ai.prompt_sha256?.slice(0, 16)}…</p>
            </>
          ) : (
            <p className="muted">{ai.error ? `Sem classificação: ${ai.error}` : "Ainda não classificado pela IA."}</p>
          )}
          {["auditor", "admin"].includes(user.role) && ai.provider.enabled && f.is_open && (
            <button className="btn small" disabled={act.busy} onClick={reclassify}>Reclassificar com IA</button>
          )}
        </section>

        <section className="card">
          <h2>Decisão do auditor</h2>
          {f.review_reasons.length > 0 && f.review_state === "pendente" && (
            <div className="warn small">Revisão obrigatória: {f.review_reasons.join(" · ")}</div>
          )}
          {f.can_decide ? (
            <>
              <label>Justificativa da decisão (obrigatória)</label>
              <textarea rows="3" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Ex.: Confirmado com o gestor; conta será desabilitada até sexta." />
              <div className="actions wrap">
                <button className="btn danger" disabled={act.busy || note.length < 5} onClick={() => decide("aprovar")}>Confirmar não conformidade</button>
                <button className="btn" disabled={act.busy || note.length < 5} onClick={() => decide("rejeitar")}>Rejeitar (falso positivo)</button>
              </div>
              <details>
                <summary className="small">Alterar classificação</summary>
                <div className="filters">
                  <select value={sev} onChange={(e) => setSev(e.target.value)}>
                    <option value="">Severidade…</option>
                    {Object.entries(SEV_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                  </select>
                  <select value={status} onChange={(e) => setStatus(e.target.value)}>
                    <option value="">Status…</option>
                    <option value="nao_conforme">Não conforme</option>
                    <option value="impossivel_avaliar">Impossível avaliar</option>
                  </select>
                  <button className="btn" disabled={act.busy || note.length < 5 || (!sev && !status)} onClick={() => decide("alterar")}>Salvar alteração</button>
                </div>
              </details>
            </>
          ) : (
            <p className="muted small">{f.decide_block_reason || (f.is_open ? "" : `Achado encerrado: ${f.resolution || ""}`)}</p>
          )}

          <h3>Histórico de decisões</h3>
          {f.decisions.length ? (
            <ul className="timeline">
              {f.decisions.map((d) => (
                <li key={d.id}>
                  <strong>{d.user}</strong> — {d.action} → <StatusBadge value={d.final_status} /> <SevBadge value={d.final_severity} />
                  <div className="small">{d.note}</div>
                  <div className="tiny muted">{fmtDate(d.created_at)} · sugestão da IA na hora: {d.ai_status_suggested || "—"}</div>
                </li>
              ))}
            </ul>
          ) : <p className="muted small">Nenhuma decisão registrada.</p>}
          <button className="btn small ghost" onClick={() => go("excecoes")}>Registrar exceção formal…</button>
        </section>
      </div>

      <section className="card">
        <h2>Evidência</h2>
        <p className="small">Trecho relevante (descriptografado):</p>
        <pre>{JSON.stringify(f.details, null, 2)}</pre>
        {["auditor", "admin"].includes(user.role) && (
          <button className="btn small" onClick={showEvidence} disabled={act.busy}>Ver evidência completa (acesso registrado)</button>
        )}
        {evidence && <pre>{JSON.stringify(evidence.payload, null, 2)}</pre>}
        <p className="tiny muted">
          Evidência {f.evidence.id} · cifrada com AES-256-GCM (chave v{f.evidence.key_version}) · hash anterior {f.evidence.prev_hash.slice(0, 16)}…
        </p>
      </section>
    </div>
  );
}
