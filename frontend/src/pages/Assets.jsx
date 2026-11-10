import React from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, fmtDate, useAction, useApi } from "../ui.jsx";

export default function Assets({ user }) {
  const { data, error, loading, reload } = useApi("/assets");
  const { data: users } = useApi("/users/options");
  const act = useAction();
  const isAdmin = user.role === "admin";

  const update = async (a, body) => {
    if (await act.run(() => api(`/assets/${a.id}`, { method: "PATCH", body }), `Ativo ${a.name} atualizado.`)) reload();
  };

  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox error={error} />;
  return (
    <div>
      <div className="page-head"><h1>Ativos e escopo</h1></div>
      <p className="muted small">
        Inventário descoberto pelos coletores. A criticidade compõe a severidade dos achados; ativos fora de escopo não são avaliados;
        o responsável pelo ativo não pode decidir sobre os próprios achados (segregação de funções).
      </p>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />
      <div className="card nopad">
        <table>
          <thead><tr><th>Ativo</th><th>Tipo</th><th>Criticidade</th><th>Em escopo</th><th>Responsável</th><th>Visto por último</th></tr></thead>
          <tbody>
            {data.map((a) => (
              <tr key={a.id}>
                <td><strong>{a.name}</strong></td>
                <td>{a.asset_type}</td>
                <td>
                  {isAdmin ? (
                    <select value={a.criticality} onChange={(e) => update(a, { criticality: Number(e.target.value) })}>
                      {[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n}</option>)}
                    </select>
                  ) : a.criticality}
                </td>
                <td>
                  {isAdmin ? (
                    <input type="checkbox" checked={a.in_scope} onChange={(e) => update(a, { in_scope: e.target.checked })} />
                  ) : a.in_scope ? "Sim" : "Não"}
                </td>
                <td>
                  {isAdmin && users ? (
                    <select value={a.owner_id || ""} onChange={(e) => update(a, e.target.value ? { owner_id: Number(e.target.value) } : { clear_owner: true })}>
                      <option value="">— sem responsável —</option>
                      {users.map((u) => <option key={u.id} value={u.id}>{u.username} ({u.role})</option>)}
                    </select>
                  ) : a.owner || "—"}
                </td>
                <td className="tiny">{fmtDate(a.last_seen_at)}</td>
              </tr>
            ))}
            {!data.length && <tr><td colSpan="6" className="muted">Nenhum ativo ainda — aguarde o primeiro ciclo de coleta.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
