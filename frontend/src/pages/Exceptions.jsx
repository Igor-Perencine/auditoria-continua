import React, { useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, useAction, useApi } from "../ui.jsx";

const EMPTY = { rule_id: "", asset_id: "", subject: "", justification: "", reference: "", expires_at: "" };

export default function Exceptions({ user }) {
  const { data, error, loading, reload } = useApi("/exceptions");
  const { data: rules } = useApi("/rules");
  const { data: assets } = useApi("/assets");
  const act = useAction();
  const [form, setForm] = useState(EMPTY);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  const canRequest = ["admin", "auditor", "gestor"].includes(user.role);

  const submit = async (e) => {
    e.preventDefault();
    const body = { ...form, asset_id: form.asset_id ? Number(form.asset_id) : null, subject: form.subject || null };
    if (await act.run(() => api("/exceptions", { method: "POST", body }), "Exceção solicitada. Outro auditor deve aprová-la.")) {
      setForm(EMPTY);
      reload();
    }
  };
  const action = async (ex, verb) => {
    if (await act.run(() => api(`/exceptions/${ex.id}/${verb}`, { method: "POST" }), "Exceção atualizada.")) reload();
  };

  return (
    <div>
      <div className="page-head"><h1>Exceções formais (risco aceito)</h1></div>
      <p className="muted small">
        Uma exceção aprovada e vigente faz a regra deixar de gerar achados para aquele ativo/objeto, evitando que o auditor reavalie
        falsos positivos. Quem solicita não pode aprovar. Exceções expiram automaticamente.
      </p>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />

      {canRequest && rules && assets && (
        <section className="card">
          <h2>Solicitar exceção</h2>
          <form onSubmit={submit}>
            <div className="row">
              <div>
                <label>Regra</label>
                <select value={form.rule_id} onChange={set("rule_id")} required>
                  <option value="">Selecione…</option>
                  {rules.map((r) => <option key={r.rule_id} value={r.rule_id}>{r.rule_id} — {r.title}</option>)}
                </select>
              </div>
              <div>
                <label>Ativo</label>
                <select value={form.asset_id} onChange={set("asset_id")}>
                  <option value="">Todos os ativos</option>
                  {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                </select>
              </div>
              <div>
                <label>Objeto (opcional)</label>
                <input value={form.subject} onChange={set("subject")} placeholder="ex.: smbv1, CVE-…, usuário" />
              </div>
            </div>
            <div className="row">
              <div><label>Referência</label><input value={form.reference} onChange={set("reference")} placeholder="EXC-2026-003" /></div>
              <div><label>Validade</label><input type="date" value={form.expires_at} onChange={set("expires_at")} required /></div>
            </div>
            <label>Justificativa e controles compensatórios</label>
            <textarea rows="3" value={form.justification} onChange={set("justification")} required minLength={10} />
            <button className="btn primary" disabled={act.busy}>Solicitar</button>
          </form>
        </section>
      )}

      {loading && !data ? <Loading /> : <ErrorBox error={error} />}
      {data && (
        <div className="card nopad">
          <table>
            <thead><tr><th>#</th><th>Regra</th><th>Ativo / objeto</th><th>Justificativa</th><th>Validade</th><th>Status</th><th>Solicitante / aprovador</th><th></th></tr></thead>
            <tbody>
              {data.map((x) => (
                <tr key={x.id}>
                  <td>{x.id}</td>
                  <td><strong>{x.rule_id}</strong><div className="tiny muted">{x.control_id} · {x.reference}</div></td>
                  <td>{x.asset || "todos"}{x.subject && <div className="tiny">{x.subject}</div>}</td>
                  <td className="wrap small">{x.justification}</td>
                  <td className={x.expired ? "warn" : ""}>{x.expires_at}{x.expired && <div className="tiny">expirada</div>}</td>
                  <td>{x.status}</td>
                  <td className="small">{x.requested_by} / {x.approved_by || "—"}</td>
                  <td>
                    {user.role === "auditor" && x.status === "solicitada" && x.requested_by !== user.username && (
                      <button className="btn small primary" onClick={() => action(x, "approve")}>Aprovar</button>
                    )}
                    {["auditor", "admin"].includes(user.role) && x.status !== "revogada" && (
                      <button className="btn small ghost" onClick={() => action(x, "revoke")}>Revogar</button>
                    )}
                  </td>
                </tr>
              ))}
              {!data.length && <tr><td colSpan="8" className="muted">Nenhuma exceção registrada.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
