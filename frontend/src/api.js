// Cliente da API. O token JWT fica em sessionStorage (some ao fechar a aba).
const KEY = "auditoria_token";
let memoryToken = null;

function readToken() {
  try {
    return sessionStorage.getItem(KEY) || memoryToken;
  } catch {
    return memoryToken;
  }
}

export function setToken(token) {
  memoryToken = token || null;
  try {
    if (token) sessionStorage.setItem(KEY, token);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* armazenamento indisponível: mantém só em memória */
  }
}

export function hasToken() {
  return !!readToken();
}

function errorMessage(data, status) {
  const d = data && data.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    return d
      .map((e) => {
        const field = Array.isArray(e.loc) ? e.loc.filter((x) => x !== "body").join(".") : "";
        return field ? `${field}: ${e.msg}` : e.msg;
      })
      .join("; ");
  }
  if (status === 429) return "Muitas tentativas. Aguarde e tente novamente.";
  if (status >= 500) return "Erro interno do servidor.";
  return `Erro ${status}`;
}

/**
 * api(path, { method, body, form })
 *  - body: objeto enviado como JSON
 *  - form: FormData (upload de arquivos)
 */
export async function api(path, { method = "GET", body, form } = {}) {
  const headers = { Accept: "application/json" };
  const token = readToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(`/api${path}`, { method, headers, body: payload });
  } catch {
    throw new Error("Não foi possível conectar ao servidor.");
  }

  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    // Sessão expirada/revogada: limpa o token e avisa o App (volta ao login).
    if (res.status === 401 && token && !path.startsWith("/auth/login") && !path.startsWith("/auth/mfa")) {
      setToken(null);
      window.dispatchEvent(new Event("auth-expired"));
    }
    throw new Error(errorMessage(data, res.status));
  }
  return data;
}
