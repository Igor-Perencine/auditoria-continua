import React, { useState } from "react";
import { api, setToken } from "../api.js";

export default function Login({ onLogin }) {
  const [stage, setStage] = useState("cred");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submitCred = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api("/auth/login", { method: "POST", body: { username, password } });
      setPassword("");
      setMfaToken(res.mfa_token);
      if (res.stage === "mfa_setup") {
        setSetup(await api("/auth/mfa/setup", { method: "POST", body: { mfa_token: res.mfa_token } }));
        setStage("setup");
      } else setStage("verify");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api("/auth/mfa/verify", { method: "POST", body: { mfa_token: mfaToken, code } });
      setToken(res.access_token);
      onLogin(res.user);
    } catch (err) {
      setError(err.message);
      setCode("");
      if (err.message.includes("expirada") || err.message.includes("inválida")) setStage("cred");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <div className="login-card">
        <h1>Auditoria Contínua</h1>
        <p className="muted">Plataforma de verificação contínua dos 93 controles da ISO/IEC 27001:2022</p>

        {stage === "cred" && (
          <form onSubmit={submitCred}>
            <label>Usuário</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus />
            <label>Senha</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            <button className="btn primary full" disabled={busy || !username || !password}>
              {busy ? "Verificando…" : "Entrar"}
            </button>
          </form>
        )}

        {stage === "setup" && setup && (
          <form onSubmit={submitCode}>
            <h3>Configure a autenticação em dois fatores</h3>
            <p className="small">
              O MFA é obrigatório. Escaneie o QR code com um aplicativo autenticador (Google Authenticator,
              Microsoft Authenticator, Aegis…) e digite o código de 6 dígitos.
            </p>
            <div className="qr">
              <img alt="QR code do MFA" src={"data:image/svg+xml;utf8," + encodeURIComponent(setup.qr_svg)} />
            </div>
            <p className="small muted">
              Ou digite a chave manualmente: <code>{setup.secret}</code>
            </p>
            <label>Código do aplicativo</label>
            <input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoFocus />
            <button className="btn primary full" disabled={busy || code.length !== 6}>
              Ativar MFA e entrar
            </button>
          </form>
        )}

        {stage === "verify" && (
          <form onSubmit={submitCode}>
            <h3>Verificação em duas etapas</h3>
            <label>Código do aplicativo autenticador</label>
            <input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" autoFocus />
            <button className="btn primary full" disabled={busy || code.length !== 6}>
              Verificar
            </button>
            <button type="button" className="btn ghost full" onClick={() => { setStage("cred"); setCode(""); }}>
              Voltar
            </button>
          </form>
        )}

        {error && <div className="error">{error}</div>}
        <p className="tiny muted">Senhas protegidas com Argon2id · MFA TOTP · Conexão TLS · Acesso registrado em trilha de auditoria</p>
      </div>
    </div>
  );
}
