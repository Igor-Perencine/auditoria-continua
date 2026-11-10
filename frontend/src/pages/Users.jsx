import React, { useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, ROLE_LABEL, fmtDate, useAction, useApi } from "../ui.jsx";

const EMPTY = { username: "", full_name: "", role: "auditor", password: "" };

export default function Users({ user }) {
  const { data, error, loading, reload } = useApi("/users");
  const act = useAction();
  const [form, setForm] = useState(EMPTY);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const create = async (e) => {
    e.preventDefault();
    if (await act.run(() => api("/users", { method: "POST", body: form }), `Usuário ${form.username} criado. O MFA será configurado no primeiro login.`)) {
      setForm(EMPTY);
      reload();
    }
  };
  const call = async (path, body, msg) => {
    if (await act.run(() => api(path, { method: body ? "PATCH" : "POST", body }), msg)) reload();
  };
  const resetPassword = async (u) => {
    const pwd = window.prompt(`Nova senha para ${u.username} (mín. 12 caracteres, 3 tipos):`);
    if (pwd) {
      if (await act.run(() => api(`/users/${u.id}/reset-password`, { method: "POST", body: { password: pwd } }), "Senha redefinida.")) reload();
    }
  };

  return (
    <div>
      <div className="page-head"><h1>Usuários e perfis</h1></div>
      <p className="muted small">
        <strong>Administrador</strong>: gerencia a plataforma, mas não decide sobre achados · <strong>Auditor</strong>: decide sobre achados e aprova exceções ·
        <strong> Gestor</strong>: vê os achados dos seus ativos e solicita exceções · <strong>Leitura</strong>: consulta.
      </p>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />
      <section className="card">
        <h2>Novo usuário</h2>
        <form onSubmit={create} className="row">
          <div><label>Usuário</label><input value={form.username} onChange={set("username")} required /></div>
          <div><label>Nome</label><input value={form.full_name} onChange={set("full_name")} /></div>
          <div>
            <label>Perfil</label>
            <select value={form.role} onChange={set("role")}>
              {Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <div><label>Senha inicial</label><input type="password" value={form.password} onChange={set("password")} required /></div>
          <div><label>&nbsp;</label><button className="btn primary" disabled={act.busy}>Criar</button></div>
        </form>
      </section>
      {loading && !data ? <Loading /> : <ErrorBox error={error} />}
      {data && (
        <div className="card nopad">
          <table>
            <thead><tr><th>Usuário</th><th>Nome</th><th>Perfil</th><th>MFA</th><th>Situação</th><th>Criado em</th><th>Ações</th></tr></thead>
            <tbody>
              {data.map((u) => (
                <tr key={u.id}>
                  <td><strong>{u.username}</strong></td>
                  <td>{u.full_name}</td>
                  <td>
                    <select value={u.role} disabled={u.id === user.id} onChange={(e) => call(`/users/${u.id}`, { role: e.target.value }, "Perfil alterado.")}>
                      {Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </td>
                  <td>{u.mfa_enabled ? "Ativo" : <span className="warn">Pendente</span>}</td>
                  <td>{!u.is_active ? "Desativado" : u.locked ? <span className="warn">Bloqueado</span> : "Ativo"}</td>
                  <td className="tiny">{fmtDate(u.created_at)}</td>
                  <td className="actions wrap">
                    {u.locked && <button className="btn small" onClick={() => call(`/users/${u.id}/unlock`, null, "Desbloqueado.")}>Desbloquear</button>}
                    <button className="btn small ghost" onClick={() => call(`/users/${u.id}/reset-mfa`, null, "MFA redefinido.")}>Redefinir MFA</button>
                    <button className="btn small ghost" onClick={() => resetPassword(u)}>Redefinir senha</button>
                    {u.id !== user.id && (
                      <button className="btn small ghost" onClick={() => call(`/users/${u.id}`, { is_active: !u.is_active }, "Situação alterada.")}>
                        {u.is_active ? "Desativar" : "Reativar"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
