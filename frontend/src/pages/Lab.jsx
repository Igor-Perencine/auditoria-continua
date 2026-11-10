import React from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, fmtDate, fmtDuration, go, useAction, useApi } from "../ui.jsx";

export default function Lab() {
  const { data, error, loading, reload } = useApi("/lab/scenarios");
  const act = useAction();

  const call = async (path, msg) => {
    if (await act.run(() => api(path, { method: "POST" }), msg)) reload();
  };
  const runNow = async () => {
    const r = await act.run(() => api("/runs", { method: "POST" }));
    if (r) {
      act.setMsg(r.started ? "Ciclo iniciado — atualize em alguns segundos para ver a detecção." : r.message);
      setTimeout(reload, 5000);
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Laboratório de cenários controlados</h1>
        <div className="actions">
          <button className="btn" onClick={reload}>Atualizar</button>
          <button className="btn" onClick={runNow} disabled={act.busy}>Executar ciclo agora</button>
          <button className="btn ghost" onClick={() => call("/lab/reset", "Ambiente restaurado ao estado de referência.")} disabled={act.busy}>Restaurar ambiente</button>
        </div>
      </div>
      <p className="muted small">
        Ambiente corporativo simulado (AD, RH, servidores, estações, backup). Injete uma falha conhecida e meça o tempo até a plataforma
        detectá-la — base dos indicadores de tempo de detecção, cobertura e falsos positivos (objetivo específico "e"). Após reverter, o
        próximo ciclo encerra o achado automaticamente (reexecução do teste).
      </p>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />
      {loading && !data ? <Loading /> : <ErrorBox error={error} />}
      {data && (
        <div className="scenarios">
          {data.map((s) => (
            <div key={s.key} className={`card scenario ${s.active ? "active" : ""}`}>
              <div className="tiny muted">{s.control} · {s.rules.join(", ")}</div>
              <h3>{s.title}</h3>
              {s.last_run && (
                <div className="small">
                  Injetado: {fmtDate(s.last_run.injected_at)}<br />
                  Detectado: {s.last_run.detected_at ? (
                    <>
                      <span className="ok-text">{fmtDuration(s.last_run.detection_seconds)} depois</span>{" "}
                      {s.last_run.finding_id && <a className="link" onClick={() => go(`achados/${s.last_run.finding_id}`)}>ver achado #{s.last_run.finding_id}</a>}
                    </>
                  ) : s.active ? <span className="warn">aguardando próximo ciclo…</span> : "—"}
                  {s.last_run.reverted_at && <><br />Revertido: {fmtDate(s.last_run.reverted_at)}</>}
                </div>
              )}
              <div className="actions">
                {s.active ? (
                  <button className="btn small" onClick={() => call(`/lab/scenarios/${s.key}/revert`, "Falha corrigida (revertida).")} disabled={act.busy}>Corrigir (reverter)</button>
                ) : (
                  <button className="btn small danger" onClick={() => call(`/lab/scenarios/${s.key}/inject`, "Falha injetada.")} disabled={act.busy}>Injetar falha</button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
