import React, { useEffect, useState } from "react";
import { api, hasToken, setToken } from "./api.js";
import { ROLE_LABEL } from "./ui.jsx";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Findings from "./pages/Findings.jsx";
import FindingDetail from "./pages/FindingDetail.jsx";
import Controls from "./pages/Controls.jsx";
import Policies from "./pages/Policies.jsx";
import Assets from "./pages/Assets.jsx";
import Exceptions from "./pages/Exceptions.jsx";
import Evidence from "./pages/Evidence.jsx";
import Lab from "./pages/Lab.jsx";
import Metrics from "./pages/Metrics.jsx";
import AuditLog from "./pages/AuditLog.jsx";
import Users from "./pages/Users.jsx";
import Settings from "./pages/Settings.jsx";
import Account from "./pages/Account.jsx";

const ALL = ["admin", "auditor", "gestor", "leitura"];
const NAV = [
  { path: "painel", label: "Painel", roles: ALL, comp: Dashboard },
  { path: "achados", label: "Triagem de achados", roles: ALL, comp: Findings },
  { path: "controles", label: "Controles (93)", roles: ALL, comp: Controls },
  { path: "politicas", label: "Políticas (RAG)", roles: ALL, comp: Policies },
  { path: "ativos", label: "Ativos e escopo", roles: ALL, comp: Assets },
  { path: "excecoes", label: "Exceções", roles: ALL, comp: Exceptions },
  { path: "evidencias", label: "Evidências e integridade", roles: ["admin", "auditor"], comp: Evidence },
  { path: "laboratorio", label: "Laboratório de cenários", roles: ["admin", "auditor"], comp: Lab },
  { path: "metricas", label: "Métricas da pesquisa", roles: ALL, comp: Metrics },
  { path: "trilha", label: "Trilha de auditoria", roles: ["admin", "auditor"], comp: AuditLog },
  { path: "usuarios", label: "Usuários", roles: ["admin"], comp: Users },
  { path: "configuracoes", label: "Parâmetros e IA", roles: ALL, comp: Settings },
  { path: "conta", label: "Minha conta", roles: ALL, comp: Account },
];

function parseHash() {
  const parts = window.location.hash.replace(/^#\/?/, "").split("/");
  return { page: parts[0] || "painel", id: parts[1] };
}

export default function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(hasToken());
  const [route, setRoute] = useState(parseHash());

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    const onExpired = () => setUser(null);
    window.addEventListener("hashchange", onHash);
    window.addEventListener("auth-expired", onExpired);
    if (hasToken()) {
      api("/auth/me")
        .then(setUser)
        .catch(() => setToken(null))
        .finally(() => setChecking(false));
    }
    return () => {
      window.removeEventListener("hashchange", onHash);
      window.removeEventListener("auth-expired", onExpired);
    };
  }, []);

  if (checking) return <div className="center muted">Carregando…</div>;
  if (!user) return <Login onLogin={setUser} />;

  const logout = async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch {
      /* sessão já expirada */
    }
    setToken(null);
    setUser(null);
  };

  const items = NAV.filter((n) => n.roles.includes(user.role));
  let content;
  if (route.page === "achados" && route.id) content = <FindingDetail id={route.id} user={user} />;
  else {
    const item = items.find((n) => n.path === route.page) || items[0];
    const Comp = item.comp;
    content = <Comp user={user} />;
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-title">Auditoria Contínua</div>
          <div className="brand-sub">ISO/IEC 27001:2022 · Anexo A</div>
        </div>
        <nav>
          {items.map((n) => (
            <a key={n.path} href={`#/${n.path}`} className={route.page === n.path ? "active" : ""}>
              {n.label}
            </a>
          ))}
        </nav>
        <div className="userbox">
          <div>
            <strong>{user.full_name || user.username}</strong>
          </div>
          <div className="muted small">
            {user.username} · {ROLE_LABEL[user.role]}
          </div>
          <button className="btn small ghost" onClick={logout}>
            Sair
          </button>
        </div>
      </aside>
      <main className="content">{content}</main>
    </div>
  );
}
