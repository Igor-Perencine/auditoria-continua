import React, { useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Loading, Notice, fmtDate, useAction, useApi } from "../ui.jsx";

function ParamRow({ p, editable, onSaved, act }) {
  const [value, setValue] = useState(p.value);
  const save = async () => {
    if (await act.run(() => api(`/parameters/${p.key}`, { method: "PUT", body: { value } }), `Parâmetro ${p.key} atualizado.`)) onSaved();
  };
  return (
    <tr>
      <td><code>{p.key}</code></td>
      <td className="wrap small">{p.description}</td>
      <td>{editable ? <input value={value} onChange={(e) => setValue(e.target.value)} /> : p.value}</td>
      <td className="tiny">{fmtDate(p.updated_at)}</td>
      <td>{editable && value !== p.value && <button className="btn small primary" onClick={save}>Salvar</button>}</td>
    </tr>
  );
}

export default function Settings({ user }) {
  const { data, error, loading, reload } = useApi("/parameters");
  const { data: ai } = useApi("/ai/status");
  const act = useAction();
  return (
    <div>
      <div className="page-head"><h1>Parâmetros de política e IA</h1></div>
      <Notice msg={act.msg} />
      <ErrorBox error={act.error} />
      {ai && (
        <section className="card">
          <h2>Inteligência artificial</h2>
          <p className="small">
            Provedor: <strong>{ai.provider}</strong> · {ai.enabled ? "ativo" : "desativado"} {ai.model && `· modelo ${ai.model}`}{" "}
            {ai.embedding_model && `· embeddings ${ai.embedding_model}`} · pseudonimização <strong>{ai.pseudonymize ? "ativa" : "desativada"}</strong>
          </p>
          {ai.warning && <div className="warn small">⚠ {ai.warning}</div>}
          <p className="tiny muted">A configuração do provedor fica no arquivo <code>.env</code> do servidor (AI_PROVIDER, GEMINI_API_KEY ou Ollama).</p>
        </section>
      )}
      <section className="card nopad">
        <h2 className="pad">Estado esperado (critérios usados pelas regras)</h2>
        <p className="muted small pad">Alterar um parâmetro muda a versão do critério registrada nos próximos achados, preservando a rastreabilidade.</p>
        {loading && !data ? <Loading /> : <ErrorBox error={error} />}
        {data && (
          <table>
            <thead><tr><th>Parâmetro</th><th>Descrição</th><th>Valor</th><th>Alterado em</th><th></th></tr></thead>
            <tbody>{data.map((p) => <ParamRow key={p.key} p={p} editable={user.role === "admin"} onSaved={reload} act={act} />)}</tbody>
          </table>
        )}
      </section>
    </div>
  );
}
