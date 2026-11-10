import React, { useState } from "react";
import { api, setToken } from "../api.js";
import { ErrorBox, Notice, ROLE_LABEL, useAction } from "../ui.jsx";

export default function Account({ user }) {
  const act = useAction();
  const [cur, setCur] = useState("");
  const [pwd, setPwd] = useState("");
  const [pwd2, setPwd2] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    if (pwd !== pwd2) return act.setError("As senhas não conferem");
    const r = await act.run(() => api("/auth/change-password", { method: "POST", body: { current_password: cur, new_password: pwd } }));
    if (r) {
      setToken(null);
      window.dispatchEvent(new Event("auth-expired"));
    }
  };

  return (
    <div>
      <div className="page-head"><h1>Minha conta</h1></div>
      <section className="card narrow">
        <p>
          <strong>{user.full_name}</strong> ({user.username}) · {ROLE_LABEL[user.role]} · MFA {user.mfa_enabled ? "ativo" : "pendente"}
        </p>
        <h2>Alterar senha</h2>
        <form onSubmit={submit}>
          <label>Senha atual</label>
          <input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" />
          <label>Nova senha (mín. 12 caracteres, ao menos 3 tipos)</label>
          <input type="password" value={pwd} onChange={(e) => setPwd(e.target.value)} autoComplete="new-password" />
          <label>Confirme a nova senha</label>
          <input type="password" value={pwd2} onChange={(e) => setPwd2(e.target.value)} autoComplete="new-password" />
          <button className="btn primary" disabled={act.busy || !cur || !pwd}>Alterar e encerrar todas as sessões</button>
        </form>
        <Notice msg={act.msg} />
        <ErrorBox error={act.error} />
      </section>
    </div>
  );
}
