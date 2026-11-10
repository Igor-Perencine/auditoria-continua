import React, { useCallback, useEffect, useState } from "react";
import { api } from "./api.js";

export const SEV_LABEL = { baixa: "Baixa", media: "Média", alta: "Alta", critica: "Crítica" };
export const STATUS_LABEL = {
  conforme: "Conforme",
  nao_conforme: "Não conforme",
  impossivel_avaliar: "Impossível avaliar",
  documentado: "Documentado",
  sem_evidencia: "Sem evidência",
  manual: "Manual",
  nao_avaliado: "Não avaliado",
  falso_positivo: "Falso positivo",
};
export const REVIEW_LABEL = { pendente: "Pendente", confirmado: "Confirmado", falso_positivo: "Falso positivo" };
export const AUTO_LABEL = { automatizavel: "Automatizável", parcial: "Parcial", documental: "Documental", manual: "Manual" };
export const ROLE_LABEL = { admin: "Administrador", auditor: "Auditor", gestor: "Gestor", leitura: "Leitura" };

export function go(path) {
  window.location.hash = "#/" + path;
}

export function Badge({ kind, value, children }) {
  return <span className={`badge ${kind}-${value}`}>{children}</span>;
}

export function SevBadge({ value }) {
  return <Badge kind="sev" value={value}>{SEV_LABEL[value] || value}</Badge>;
}

export function StatusBadge({ value }) {
  return <Badge kind="st" value={value}>{STATUS_LABEL[value] || value}</Badge>;
}

export function fmtDate(v) {
  return v ? new Date(v).toLocaleString("pt-BR") : "—";
}

export function fmtDuration(sec) {
  if (sec === null || sec === undefined) return "—";
  if (sec < 60) return `${Math.round(sec)} s`;
  if (sec < 3600) return `${(sec / 60).toFixed(1)} min`;
  if (sec < 86400) return `${(sec / 3600).toFixed(1)} h`;
  return `${(sec / 86400).toFixed(1)} dias`;
}

export function useApi(path) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    if (!path) return;
    setLoading(true);
    setError(null);
    try {
      setData(await api(path));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    load();
  }, [load]);
  return { data, error, loading, reload: load, setData };
}

export function Loading() {
  return <div className="muted">Carregando…</div>;
}

export function ErrorBox({ error }) {
  return error ? <div className="error">{error}</div> : null;
}

export function Notice({ msg }) {
  return msg ? <div className="notice">{msg}</div> : null;
}

export function Stat({ label, value, hint, tone }) {
  return (
    <div className={`stat ${tone || ""}`}>
      <div className="stat-value">{value ?? "—"}</div>
      <div className="stat-label">{label}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

// Executa uma ação assíncrona com estado de carregamento e mensagens.
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [msg, setMsg] = useState(null);
  const run = async (fn, okMsg) => {
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      const r = await fn();
      if (okMsg) setMsg(okMsg);
      return r;
    } catch (e) {
      setError(e.message);
      return null;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, msg, run, setMsg, setError };
}
