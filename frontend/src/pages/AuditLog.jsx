import React, { useState } from "react";
import { ErrorBox, Loading, fmtDate, useApi } from "../ui.jsx";

export default function AuditLog() {
  const [action, setAction] = useState("");
  const { data, error, loading, reload } = useApi(`/audit-log?limit=300${action ? `&action=${encodeURIComponent(action)}` : ""}`);
  return (
    <div>
      <div className="page-head">
        <h1>Trilha de auditoria da plataforma</h1>
        <button className="btn" onClick={reload}>Atualizar</button>
      </div>
      <p className="muted small">Registro imutável (encadeado por hash) de logins, decisões, alterações de parâmetros, acessos a evidências e ações da IA.</p>
      <div className="filters">
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">Todas as ações</option>
          {["login_sucesso", "login_falha", "conta_bloqueada", "decisao_achado", "ia_classificacao", "evidencia_visualizada",
            "parametro_alterado", "politica_carregada", "excecao_aprovada", "cenario_injetado", "ciclo_auditoria", "integridade_verificada"].map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
      </div>
      {loading && !data ? <Loading /> : <ErrorBox error={error} />}
      {data && (
        <div className="card nopad">
          <table>
            <thead><tr><th>Seq</th><th>Data/hora</th><th>Usuário</th><th>Ação</th><th>Alvo</th><th>Detalhes</th><th>IP</th><th>Hash</th></tr></thead>
            <tbody>
              {data.map((e) => (
                <tr key={e.seq}>
                  <td>{e.seq}</td><td className="tiny">{fmtDate(e.ts)}</td><td>{e.username}</td><td><code>{e.action}</code></td>
                  <td className="small">{e.target}</td>
                  <td className="tiny mono wrap">{Object.keys(e.details || {}).length ? JSON.stringify(e.details) : ""}</td>
                  <td className="tiny">{e.ip || ""}</td><td className="tiny mono">{e.hash.slice(0, 10)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
