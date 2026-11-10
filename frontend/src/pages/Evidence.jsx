import React, { useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, fmtDate, useAction, useApi } from "../ui.jsx";

function ChainResult({ title, r }) {
  return (
    <div className={`chain ${r.ok ? "ok" : "bad"}`}>
      <strong>{title}: {r.ok ? "ÍNTEGRA ✓" : "VIOLADA ✗"}</strong>
      <div className="small">{r.count} registros verificados{r.ok && r.last_hash ? ` · último hash ${r.last_hash.slice(0, 16)}…` : ""}</div>
      {!r.ok && <div className="small">Quebra no registro #{r.broken_at}: {r.reason}</div>}
    </div>
  );
}

export default function Evidence() {
  const { data, error, loading, reload } = useApi("/evidence?limit=150");
  const act = useAction();
  const [verify, setVerify] = useState(null);
  const [selected, setSelected] = useState(null);

  const runVerify = async () => {
    const r = await act.run(() => api("/integrity/verify", { method: "POST" }));
    if (r) setVerify(r);
  };
  const open = async (id) => {
    const r = await act.run(() => api(`/evidence/${id}`));
    if (r) setSelected(r);
  };

  return (
    <div>
      <div className="page-head">
        <h1>Evidências e integridade</h1>
        <div className="actions">
          <button className="btn" onClick={reload}>Atualizar</button>
          <button className="btn primary" onClick={runVerify} disabled={act.busy}>Verificar integridade</button>
        </div>
      </div>
      <p className="muted small">
        Cada evidência é cifrada com AES-256-GCM (chave por registro, protegida pela chave mestra fora do banco) e encadeada por
        SHA-256 ao registro anterior. Alterar, inserir ou apagar qualquer linha diretamente no banco quebra a cadeia. A trilha de
        auditoria da plataforma usa o mesmo mecanismo.
      </p>
      <ErrorBox error={act.error} />
      {verify && (
        <div className="grid2">
          <ChainResult title="Cadeia de evidências" r={verify.evidence} />
          <ChainResult title="Trilha de auditoria" r={verify.audit_log} />
        </div>
      )}
      {selected && (
        <section className="card">
          <div className="page-head">
            <h2>Evidência #{selected.seq} — {selected.asset} ({selected.kind})</h2>
            <button className="btn small ghost" onClick={() => setSelected(null)}>Fechar</button>
          </div>
          <p className="tiny muted">{selected.source} · {fmtDate(selected.collected_at)} · hash {selected.hash}</p>
          <pre>{JSON.stringify(selected.payload, null, 2)}</pre>
        </section>
      )}
      {loading && !data ? <Loading /> : <ErrorBox error={error} />}
      {data && (
        <div className="card nopad">
          <table className="clickable">
            <thead><tr><th>Seq</th><th>Ativo</th><th>Tipo</th><th>Fonte</th><th>Controles</th><th>Coletada em</th><th>Hash</th><th>Hash anterior</th></tr></thead>
            <tbody>
              {data.map((e) => (
                <tr key={e.id} onClick={() => open(e.id)}>
                  <td>{e.seq}</td><td>{e.asset}</td><td>{e.kind}</td><td className="small">{e.source}</td>
                  <td className="tiny">{e.control_ids.join(", ")}</td><td className="tiny">{fmtDate(e.collected_at)}</td>
                  <td className="tiny mono">{e.hash.slice(0, 12)}…</td><td className="tiny mono muted">{e.prev_hash.slice(0, 12)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
