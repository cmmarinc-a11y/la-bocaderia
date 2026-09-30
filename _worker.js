function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...rest] = cookie.trim().split("=");
    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64ToBytes(base64) {
  const normalized = base64
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function hashPassword(password, saltBytes, iterations = 100000) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const hash = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  return new Uint8Array(hash);
}

async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100000;

  const hash = await hashPassword(password, salt, iterations);

  return [
    "pbkdf2",
    iterations,
    bytesToBase64(salt),
    bytesToBase64(hash)
  ].join("$");
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split("$");

    if (parts.length !== 4 || parts[0] !== "pbkdf2") {
      return false;
    }

    const iterations = Number(parts[1]);
    const salt = base64ToBytes(parts[2]);
    const expectedHash = base64ToBytes(parts[3]);

    const actualHash = await hashPassword(
      password,
      salt,
      iterations
    );

    if (actualHash.length !== expectedHash.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0; i < actualHash.length; i++) {
      difference |= actualHash[i] ^ expectedHash[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

async function createSession(env, userId) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToBase64(tokenBytes);

  const tokenHashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  const tokenHash = bytesToBase64(
    new Uint8Array(tokenHashBuffer)
  );

  const sessionId = tokenHash;

  const expiresAt = new Date(
    Date.now() + 1000 * 60 * 60 * 24 * 30
  ).toISOString();

  await env.DB.prepare(`
    INSERT INTO sessions (id, user_id, expires_at)
    VALUES (?, ?, ?)
  `)
    .bind(sessionId, userId, expiresAt)
    .run();

  return { token, expiresAt };
}

async function getSessionUser(request, env) {
  const token = getCookie(request, "lb_session");

  if (!token) {
    return null;
  }

  const tokenHashBuffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  const tokenHash = bytesToBase64(
    new Uint8Array(tokenHashBuffer)
  );

  const session = await env.DB.prepare(`
    SELECT
      sessions.id,
      sessions.user_id,
      sessions.expires_at,
      users.username,
      users.name
    FROM sessions
    INNER JOIN users
      ON users.id = sessions.user_id
    WHERE sessions.id = ?
      AND users.active = 1
  `)
    .bind(tokenHash)
    .first();

  if (!session) {
    return null;
  }

  if (new Date(session.expires_at) <= new Date()) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE id = ?
    `)
      .bind(session.id)
      .run();

    return null;
  }

  return session;
}

async function handleLogin(request, env) {
  if (request.method !== "POST") {
    return json({ error: "Método no permitido" }, 405);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ error: "Solicitud inválida" }, 400);
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  if (!username || !password) {
    return json(
      { error: "Usuario y contraseña son obligatorios" },
      400
    );
  }

  const user = await env.DB.prepare(`
    SELECT id, username, password_hash, name
    FROM users
    WHERE username = ?
      AND active = 1
  `)
    .bind(username)
    .first();

  if (!user) {
    return json(
      { error: "Usuario o contraseña incorrectos" },
      401
    );
  }

  const validPassword = await verifyPassword(
    password,
    user.password_hash
  );

  if (!validPassword) {
    return json(
      { error: "Usuario o contraseña incorrectos" },
      401
    );
  }

  const { token, expiresAt } = await createSession(
    env,
    user.id
  );

  const response = json({
    ok: true,
    user: {
      username: user.username,
      name: user.name
    }
  });

  response.headers.set(
    "Set-Cookie",
    `lb_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${new Date(expiresAt).toUTCString()}`
  );

  return response;
}

async function handleMe(request, env) {
  if (request.method !== "GET") {
    return json({ error: "Método no permitido" }, 405);
  }

  const session = await getSessionUser(request, env);

  if (!session) {
    return json(
      { authenticated: false },
      401
    );
  }

  return json({
    authenticated: true,
    user: {
      username: session.username,
      name: session.name
    }
  });
}

async function handleLogout(request, env) {
  if (request.method !== "POST") {
    return json({ error: "Método no permitido" }, 405);
  }

  const token = getCookie(request, "lb_session");

  if (token) {
    const tokenHashBuffer = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(token)
    );

    const tokenHash = bytesToBase64(
      new Uint8Array(tokenHashBuffer)
    );

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE id = ?
    `)
      .bind(tokenHash)
      .run();
  }

  const response = json({ ok: true });

  response.headers.set(
    "Set-Cookie",
    "lb_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );

  return response;
}

async function handleSetup(request, env) {
  if (request.method !== "POST") {
    return json({ error: "Método no permitido" }, 405);
  }

  if (!env.SETUP_KEY) {
    return json({ error: "SETUP_KEY no configurado" }, 500);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ error: "Solicitud inválida" }, 400);
  }

  const setupKey = String(body.setupKey || "");
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  const name = String(body.name || "").trim();

  if (setupKey !== env.SETUP_KEY) {
    return json({ error: "No autorizado" }, 401);
  }

  if (!username || !password) {
    return json(
      { error: "Usuario y contraseña son obligatorios" },
      400
    );
  }

  const existingUser = await env.DB.prepare(`
    SELECT id
    FROM users
    WHERE username = ?
  `)
    .bind(username)
    .first();

  if (existingUser) {
    return json(
      { error: "El usuario ya existe" },
      409
    );
  }

  const passwordHash = await createPasswordHash(password);
  const userId = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO users (
      id,
      username,
      password_hash,
      name,
      active
    )
    VALUES (?, ?, ?, ?, 1)
  `)
    .bind(
      userId,
      username,
      passwordHash,
      name || username
    )
    .run();

  return json({
    ok: true,
    message: "Usuario creado correctamente",
    username
  });
}
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/login") {
      return handleLogin(request, env);
    }

    if (url.pathname === "/api/me") {
      return handleMe(request, env);
    }

    if (url.pathname === "/api/logout") {
      return handleLogout(request, env);
    }

    return env.ASSETS.fetch(request);
  }
};
