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

  const hash = await hashPassword(
    password,
    salt,
    iterations
  );

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
  const tokenBytes = crypto.getRandomValues(
    new Uint8Array(32)
  );

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
    .bind(
      sessionId,
      userId,
      expiresAt
    )
    .run();

  return {
    token,
    expiresAt
  };
}

async function getSessionUser(request, env) {
  const token = getCookie(
    request,
    "lb_session"
  );

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

  if (
    new Date(session.expires_at) <=
    new Date()
  ) {
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
    return json(
      { error: "Método no permitido" },
      405
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      { error: "Solicitud inválida" },
      400
    );
  }

  const username = String(
    body.username || ""
  ).trim();

  const password = String(
    body.password || ""
  );

  if (!username || !password) {
    return json(
      {
        error:
          "Usuario y contraseña son obligatorios"
      },
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
      {
        error:
          "Usuario o contraseña incorrectos"
      },
      401
    );
  }

  const validPassword =
    await verifyPassword(
      password,
      user.password_hash
    );

  if (!validPassword) {
    return json(
      {
        error:
          "Usuario o contraseña incorrectos"
      },
      401
    );
  }

  const {
    token,
    expiresAt
  } = await createSession(
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
    `lb_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${new Date(
      expiresAt
    ).toUTCString()}`
  );

  return response;
}

async function handleMe(request, env) {
  if (request.method !== "GET") {
    return json(
      { error: "Método no permitido" },
      405
    );
  }

  const session =
    await getSessionUser(
      request,
      env
    );

  if (!session) {
    return json(
      {
        authenticated: false
      },
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
    return json(
      { error: "Método no permitido" },
      405
    );
  }

  const token = getCookie(
    request,
    "lb_session"
  );

  if (token) {
    const tokenHashBuffer =
      await crypto.subtle.digest(
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

  const response = json({
    ok: true
  });

  response.headers.set(
    "Set-Cookie",
    "lb_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );

  return response;
}

async function handleSetup(request, env) {
  if (request.method !== "POST") {
    return json(
      { error: "Método no permitido" },
      405
    );
  }

  if (!env.SETUP_KEY) {
    return json(
      {
        error:
          "SETUP_KEY no configurado"
      },
      500
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        error:
          "Solicitud inválida"
      },
      400
    );
  }

  const setupKey = String(
    body.setupKey || ""
  );

  const username = String(
    body.username || ""
  ).trim();

  const password = String(
    body.password || ""
  );

  const name = String(
    body.name || ""
  ).trim();

  if (setupKey !== env.SETUP_KEY) {
    return json(
      {
        error:
          "No autorizado"
      },
      401
    );
  }

  if (!username || !password) {
    return json(
      {
        error:
          "Usuario y contraseña son obligatorios"
      },
      400
    );
  }

  const existingUser =
    await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE username = ?
    `)
      .bind(username)
      .first();

  if (existingUser) {
    return json(
      {
        error:
          "El usuario ya existe"
      },
      409
    );
  }

  const passwordHash =
    await createPasswordHash(
      password
    );

  const userId =
    crypto.randomUUID();

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
    message:
      "Usuario creado correctamente",
    username
  });
}

async function handleDbTest(request, env) {
  try {
    const result = await env.DB
      .prepare("SELECT COUNT(*) AS total FROM ingredients")
      .first();

    return json({
      ok: true,
      message: "D1 conectado correctamente",
      ingredients: result?.total ?? 0
    });
  } catch (error) {
    return json({
      ok: false,
      message: "Error conectando con D1",
      error: error.message
    }, 500);
  }
}
// =====================================================
// D1 — CATÁLOGO: INGREDIENTES, OTROS INSUMOS Y RECETAS
// =====================================================

async function handleCatalog(request, env) {
  try {
    const user = await getSessionUser(request, env);

    if (!user) {
      return json({ error: "No autorizado" }, 401);
    }

    // -----------------------------
    // GET — cargar catálogo
    // -----------------------------
    if (request.method === "GET") {
      const [
        ingredientsResult,
        suppliesResult,
        recipesResult,
        recipeIngredientsResult
      ] = await env.DB.batch([
        env.DB.prepare(`
          SELECT id, name, unit, status, created_at, updated_at
          FROM ingredients
          ORDER BY name COLLATE NOCASE
        `),

        env.DB.prepare(`
          SELECT id, name, unit, consumable, status, created_at, updated_at
          FROM other_supplies
          ORDER BY name COLLATE NOCASE
        `),

        env.DB.prepare(`
          SELECT id, name, sale_price, status, created_at, updated_at
          FROM recipes
          ORDER BY name COLLATE NOCASE
        `),

        env.DB.prepare(`
          SELECT
            ri.id,
            ri.recipe_id,
            ri.ingredient_id,
            ri.quantity
          FROM recipe_ingredients ri
          ORDER BY ri.id
        `)
      ]);

      const ingredients = ingredientsResult.results || [];
      const supplies = suppliesResult.results || [];
      const recipesRows = recipesResult.results || [];
      const recipeIngredients = recipeIngredientsResult.results || [];

      // Convertimos receta + recipe_ingredients
      // al formato que actualmente entiende la app.
      const recipes = recipesRows.map(recipe => {
        const recipeIngredientRows = recipeIngredients.filter(
          row => row.recipe_id === recipe.id
        );

        const ingredientMap = {};

        recipeIngredientRows.forEach(row => {
          const ingredient = ingredients.find(
            item => item.id === row.ingredient_id
          );

          if (ingredient) {
            ingredientMap[ingredient.name] = Number(row.quantity) || 0;
          }
        });

        return {
          id: recipe.id,
          name: recipe.name,
          salePrice: Number(recipe.sale_price) || 0,
          status: recipe.status || "active",
          ingredients: ingredientMap,
          supplies: {}
        };
      });

      return json({
        ok: true,
        ingredients,
        otherSupplies: supplies,
        recipes
      });
    }

    // -----------------------------
    // POST — guardar cambios
    // -----------------------------
    if (request.method === "POST") {
      const body = await request.json();
      const { type, action, data } = body;

      // =================================================
      // INGREDIENTES
      // =================================================
      if (type === "ingredient") {

        if (action === "create") {
          const id = data.id || uidServer("ing");

          await env.DB.prepare(`
            INSERT INTO ingredients
              (id, name, unit, status)
            VALUES (?, ?, ?, ?)
          `).bind(
            id,
            data.name,
            data.unit || "g",
            data.status || "active"
          ).run();

          return json({
            ok: true,
            id
          });
        }

        if (action === "update") {
          await env.DB.prepare(`
            UPDATE ingredients
            SET name = ?,
                unit = ?,
                status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(
            data.name,
            data.unit || "g",
            data.status || "active",
            data.id
          ).run();

          return json({ ok: true });
        }

        if (action === "delete") {
          await env.DB.prepare(`
            DELETE FROM ingredients
            WHERE id = ?
          `).bind(data.id).run();

          return json({ ok: true });
        }
      }

      // =================================================
      // OTROS INSUMOS
      // =================================================
      if (type === "supply") {

        if (action === "create") {
          const id = data.id || uidServer("os");

          await env.DB.prepare(`
            INSERT INTO other_supplies
              (id, name, unit, consumable, status)
            VALUES (?, ?, ?, ?, ?)
          `).bind(
            id,
            data.name,
            data.unit || "un",
            data.consumable === false ? 0 : 1,
            data.status || "active"
          ).run();

          return json({
            ok: true,
            id
          });
        }

        if (action === "update") {
          await env.DB.prepare(`
            UPDATE other_supplies
            SET name = ?,
                unit = ?,
                consumable = ?,
                status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(
            data.name,
            data.unit || "un",
            data.consumable === false ? 0 : 1,
            data.status || "active",
            data.id
          ).run();

          return json({ ok: true });
        }

        if (action === "delete") {
          await env.DB.prepare(`
            DELETE FROM other_supplies
            WHERE id = ?
          `).bind(data.id).run();

          return json({ ok: true });
        }
      }

      // =================================================
      // RECETAS
      // =================================================
      if (type === "recipe") {

        if (action === "create") {
          const recipeId = data.id || uidServer("r");

          const statements = [
            env.DB.prepare(`
              INSERT INTO recipes
                (id, name, sale_price, status)
              VALUES (?, ?, ?, ?)
            `).bind(
              recipeId,
              data.name,
              Number(data.salePrice) || 0,
              data.status || "active"
            )
          ];

          const ingredientEntries = Object.entries(
            data.ingredients || {}
          );

          for (const [ingredientName, quantity] of ingredientEntries) {

            const ingredient = await env.DB.prepare(`
              SELECT id
              FROM ingredients
              WHERE name = ?
              LIMIT 1
            `).bind(ingredientName).first();

            if (!ingredient) {
              throw new Error(
                `No se encontró el ingrediente: ${ingredientName}`
              );
            }

            statements.push(
              env.DB.prepare(`
                INSERT INTO recipe_ingredients
                  (id, recipe_id, ingredient_id, quantity)
                VALUES (?, ?, ?, ?)
              `).bind(
                uidServer("ri"),
                recipeId,
                ingredient.id,
                Number(quantity) || 0
              )
            );
          }

          await env.DB.batch(statements);

          return json({
            ok: true,
            id: recipeId
          });
        }

        if (action === "update") {

          const recipeId = data.id;

          const statements = [
            env.DB.prepare(`
              UPDATE recipes
              SET name = ?,
                  sale_price = ?,
                  status = ?,
                  updated_at = CURRENT_TIMESTAMP
              WHERE id = ?
            `).bind(
              data.name,
              Number(data.salePrice) || 0,
              data.status || "active",
              recipeId
            ),

            env.DB.prepare(`
              DELETE FROM recipe_ingredients
              WHERE recipe_id = ?
            `).bind(recipeId)
          ];

          const ingredientEntries = Object.entries(
            data.ingredients || {}
          );

          for (const [ingredientName, quantity] of ingredientEntries) {

            const ingredient = await env.DB.prepare(`
              SELECT id
              FROM ingredients
              WHERE name = ?
              LIMIT 1
            `).bind(ingredientName).first();

            if (!ingredient) {
              throw new Error(
                `No se encontró el ingrediente: ${ingredientName}`
              );
            }

            statements.push(
              env.DB.prepare(`
                INSERT INTO recipe_ingredients
                  (id, recipe_id, ingredient_id, quantity)
                VALUES (?, ?, ?, ?)
              `).bind(
                uidServer("ri"),
                recipeId,
                ingredient.id,
                Number(quantity) || 0
              )
            );
          }

          await env.DB.batch(statements);

          return json({ ok: true });
        }

        if (action === "delete") {

          await env.DB.batch([
            env.DB.prepare(`
              DELETE FROM recipe_ingredients
              WHERE recipe_id = ?
            `).bind(data.id),

            env.DB.prepare(`
              DELETE FROM recipes
              WHERE id = ?
            `).bind(data.id)
          ]);

          return json({ ok: true });
        }
      }

      return json({
        ok: false,
        error: "Tipo o acción no reconocidos"
      }, 400);
    }

    return json({
      error: "Método no permitido"
    }, 405);

  } catch (error) {
    console.error("Error en catálogo D1:", error);

    return json({
      ok: false,
      error: error.message
    }, 500);
  }
}


// Generador de IDs del Worker
function uidServer(prefix) {
  return prefix + "-" + crypto.randomUUID();
}
// =====================================================
// D1 — CLIENTES Y PROVEEDORES
// =====================================================

async function handleContacts(request, env) {
  try {
    const user = await getSessionUser(request, env);

    if (!user) {
      return json({ error: "No autorizado" }, 401);
    }

    // -----------------------------
    // GET — cargar clientes y proveedores
    // -----------------------------
    if (request.method === "GET") {

      const [
        clientsResult,
        suppliersResult
      ] = await env.DB.batch([

        env.DB.prepare(`
          SELECT
            id,
            name,
            phone,
            location,
            note,
            status,
            created_at,
            updated_at
          FROM clients
          ORDER BY name COLLATE NOCASE
        `),

        env.DB.prepare(`
          SELECT
            id,
            name,
            supplies,
            location,
            contact,
            status,
            created_at,
            updated_at
          FROM suppliers
          ORDER BY name COLLATE NOCASE
        `)

      ]);

      return json({
        ok: true,
        clients: clientsResult.results || [],
        suppliers: suppliersResult.results || []
      });
    }

    // -----------------------------
    // POST — guardar cambios
    // -----------------------------
    if (request.method === "POST") {

      const body = await request.json();
      const { type, action, data } = body;

      // =================================================
      // CLIENTES
      // =================================================

      if (type === "client") {

        // CREAR
        if (action === "create") {

          const id = data.id || uidServer("c");

          await env.DB.prepare(`
            INSERT INTO clients
              (id, name, phone, location, note, status)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(
            id,
            data.name,
            data.phone || "",
            data.location || "",
            data.note || "",
            data.status || "active"
          ).run();

          return json({
            ok: true,
            id
          });
        }

        // ACTUALIZAR
        if (action === "update") {

          await env.DB.prepare(`
            UPDATE clients
            SET
              name = ?,
              phone = ?,
              location = ?,
              note = ?,
              status = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(
            data.name,
            data.phone || "",
            data.location || "",
            data.note || "",
            data.status || "active",
            data.id
          ).run();

          return json({
            ok: true
          });
        }

        // CAMBIAR ESTADO
        if (action === "status") {

          await env.DB.prepare(`
            UPDATE clients
            SET
              status = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(
            data.status,
            data.id
          ).run();

          return json({
            ok: true
          });
        }

        // ELIMINAR
        if (action === "delete") {

          // Verificar si el cliente tiene pedidos
          const history = await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM orders
            WHERE client_id = ?
          `).bind(data.id).first();

          if (Number(history?.count || 0) > 0) {
            return json({
              ok: false,
              error: "No se puede eliminar este cliente porque tiene pedidos asociados."
            }, 400);
          }

          await env.DB.prepare(`
            DELETE FROM clients
            WHERE id = ?
          `).bind(data.id).run();

          return json({
            ok: true
          });
        }
      }

      // =================================================
      // PROVEEDORES
      // =================================================

      if (type === "supplier") {

        // CREAR
        if (action === "create") {

          const id = data.id || uidServer("sup");

          await env.DB.prepare(`
            INSERT INTO suppliers
              (id, name, supplies, location, contact, status)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(
            id,
            data.name,
            data.supplies || "",
            data.location || "",
            data.contact || "",
            data.status || "active"
          ).run();

          return json({
            ok: true,
            id
          });
        }

        // ACTUALIZAR
        if (action === "update") {

          await env.DB.prepare(`
            UPDATE suppliers
            SET
              name = ?,
              supplies = ?,
              location = ?,
              contact = ?,
              status = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(
            data.name,
            data.supplies || "",
            data.location || "",
            data.contact || "",
            data.status || "active",
            data.id
          ).run();

          return json({
            ok: true
          });
        }

        // CAMBIAR ESTADO
        if (action === "status") {

          await env.DB.prepare(`
            UPDATE suppliers
            SET
              status = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(
            data.status,
            data.id
          ).run();

          return json({
            ok: true
          });
        }

        // ELIMINAR
        if (action === "delete") {

          // Verificar si el proveedor tiene compras
          const history = await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM purchases
            WHERE supplier_id = ?
          `).bind(data.id).first();

          if (Number(history?.count || 0) > 0) {
            return json({
              ok: false,
              error: "No se puede eliminar este proveedor porque tiene compras asociadas."
            }, 400);
          }

          await env.DB.prepare(`
            DELETE FROM suppliers
            WHERE id = ?
          `).bind(data.id).run();

          return json({
            ok: true
          });
        }
      }

      return json({
        ok: false,
        error: "Tipo o acción no reconocidos"
      }, 400);
    }

    return json({
      error: "Método no permitido"
    }, 405);

  } catch (error) {

    console.error("Error en clientes/proveedores D1:", error);

    return json({
      ok: false,
      error: error.message
    }, 500);
  }
}
// =====================================================
// D1 — PEDIDOS
// =====================================================

async function handleOrders(request, env) {
  try {
    const user = await getSessionUser(request, env);

    if (!user) {
      return json({ error: "No autorizado" }, 401);
    }

    // =================================================
    // GET — cargar pedidos
    // =================================================

    if (request.method === "GET") {

      const [
        ordersResult,
        itemsResult
      ] = await env.DB.batch([

        env.DB.prepare(`
          SELECT
            o.id,
            o.number,
            o.client_id,
            c.name AS client_name,
            o.date,
            o.time,
            o.deposit,
            o.balance,
            o.note,
            o.status,
            o.created_at,
            o.updated_at
          FROM orders o
          LEFT JOIN clients c
            ON c.id = o.client_id
          ORDER BY o.date DESC, o.time DESC, o.created_at DESC
        `),

        env.DB.prepare(`
          SELECT
            oi.id,
            oi.order_id,
            oi.recipe_id,
            r.name AS recipe_name,
            oi.quantity,
            oi.unit_price,
            oi.subtotal,
            oi.created_at,
            oi.updated_at
          FROM order_items oi
          LEFT JOIN recipes r
            ON r.id = oi.recipe_id
          ORDER BY oi.order_id, oi.id
        `)

      ]);

      const ordersRows = ordersResult.results || [];
      const itemsRows = itemsResult.results || [];

      const orders = ordersRows.map(order => {

        const items = itemsRows
          .filter(item => item.order_id === order.id)
          .map(item => ({
            id: item.id,
            recipeId: item.recipe_id,
            product: item.recipe_name || "",
            qty: Number(item.quantity) || 0,
            unitPrice: Number(item.unit_price) || 0,
            subtotal: Number(item.subtotal) || 0
          }));

        return {
          id: order.id,
          number: order.number,
          clientId: order.client_id,
          clientName: order.client_name || "",
          date: order.date,
          time: order.time,
          deposit: Number(order.deposit) || 0,
          balance: Number(order.balance) || 0,
          note: order.note || "",
          status: order.status || "Solicitado",
          items
        };
      });

      return json({
        ok: true,
        orders
      });
    }

    // =================================================
    // POST — guardar cambios
    // =================================================

    if (request.method === "POST") {

      const body = await request.json();
      const { action, data } = body;

      // =================================================
      // CREAR PEDIDO
      // =================================================

      if (action === "create") {

        const orderId = data.id || uidServer("o");

        const orderNumber =
          data.number ||
          await generateOrderNumber(env);

        const items = Array.isArray(data.items)
          ? data.items
          : [];

        const statements = [];

        statements.push(
          env.DB.prepare(`
            INSERT INTO orders
              (
                id,
                number,
                client_id,
                date,
                time,
                deposit,
                balance,
                note,
                status
              )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            orderId,
            orderNumber,
            data.clientId || null,
            data.date || null,
            data.time || null,
            Number(data.deposit) || 0,
            Number(data.balance) || 0,
            data.note || "",
            data.status || "Solicitado"
          )
        );

        for (const item of items) {

          const quantity = Number(item.qty) || 0;
          const unitPrice = Number(item.unitPrice) || 0;
          const subtotal =
            Number(item.subtotal) ||
            quantity * unitPrice;

          statements.push(
            env.DB.prepare(`
              INSERT INTO order_items
                (
                  id,
                  order_id,
                  recipe_id,
                  quantity,
                  unit_price,
                  subtotal
                )
              VALUES (?, ?, ?, ?, ?, ?)
            `).bind(
              item.id || uidServer("oi"),
              orderId,
              item.recipeId || null,
              quantity,
              unitPrice,
              subtotal
            )
          );
        }

        await env.DB.batch(statements);

        return json({
          ok: true,
          id: orderId,
          number: orderNumber
        });
      }

      // =================================================
      // ACTUALIZAR PEDIDO
      // =================================================

      if (action === "update") {

        const orderId = data.id;

        const items = Array.isArray(data.items)
          ? data.items
          : [];

        const statements = [

          env.DB.prepare(`
            UPDATE orders
            SET
              number = ?,
              client_id = ?,
              date = ?,
              time = ?,
              deposit = ?,
              balance = ?,
              note = ?,
              status = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(
            data.number,
            data.clientId || null,
            data.date || null,
            data.time || null,
            Number(data.deposit) || 0,
            Number(data.balance) || 0,
            data.note || "",
            data.status || "Solicitado",
            orderId
          ),

          env.DB.prepare(`
            DELETE FROM order_items
            WHERE order_id = ?
          `).bind(orderId)

        ];

        for (const item of items) {

          const quantity = Number(item.qty) || 0;
          const unitPrice = Number(item.unitPrice) || 0;
          const subtotal =
            Number(item.subtotal) ||
            quantity * unitPrice;

          statements.push(
            env.DB.prepare(`
              INSERT INTO order_items
                (
                  id,
                  order_id,
                  recipe_id,
                  quantity,
                  unit_price,
                  subtotal
                )
              VALUES (?, ?, ?, ?, ?, ?)
            `).bind(
              item.id || uidServer("oi"),
              orderId,
              item.recipeId || null,
              quantity,
              unitPrice,
              subtotal
            )
          );
        }

        await env.DB.batch(statements);

        return json({
          ok: true
        });
      }

      // =================================================
      // CAMBIAR ESTADO
      // =================================================

      if (action === "status") {

        const validStatuses = [
          "Solicitado",
          "Preparación",
          "Preparado",
          "Entregado",
          "Cancelado"
        ];

        if (!validStatuses.includes(data.status)) {
          return json({
            ok: false,
            error: "Estado de pedido no válido"
          }, 400);
        }

        await env.DB.prepare(`
          UPDATE orders
          SET
            status = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(
          data.status,
          data.id
        ).run();

        return json({
          ok: true
        });
      }

      // =================================================
      // ELIMINAR PEDIDO
      // =================================================

      if (action === "delete") {

        const productionHistory = await env.DB.prepare(`
          SELECT COUNT(*) AS count
          FROM production
          WHERE order_id = ?
        `).bind(data.id).first();

        if (Number(productionHistory?.count || 0) > 0) {
          return json({
            ok: false,
            error: "No se puede eliminar este pedido porque tiene producción asociada."
          }, 400);
        }

        await env.DB.batch([

          env.DB.prepare(`
            DELETE FROM order_items
            WHERE order_id = ?
          `).bind(data.id),

          env.DB.prepare(`
            DELETE FROM orders
            WHERE id = ?
          `).bind(data.id)

        ]);

        return json({
          ok: true
        });
      }

      return json({
        ok: false,
        error: "Acción no reconocida"
      }, 400);
    }

    return json({
      error: "Método no permitido"
    }, 405);

  } catch (error) {

    console.error("Error en pedidos D1:", error);

    return json({
      ok: false,
      error: error.message
    }, 500);
  }
}


// =====================================================
// GENERADOR DE NÚMERO DE PEDIDO
// =====================================================

async function generateOrderNumber(env) {

  const row = await env.DB.prepare(`
    SELECT number
    FROM orders
    WHERE number LIKE 'LB-%'
    ORDER BY CAST(SUBSTR(number, 4) AS INTEGER) DESC
    LIMIT 1
  `).first();

  let nextNumber = 1;

  if (row?.number) {
    const current =
      Number(String(row.number).replace("LB-", "")) || 0;

    nextNumber = current + 1;
  }

  return "LB-" + String(nextNumber).padStart(5, "0");
}
// =====================================================
// D1 — COMPRAS
// =====================================================

async function handlePurchases(request, env) {
  try {
    const user = await getSessionUser(request, env);

    if (!user) {
      return json({ error: "No autorizado" }, 401);
    }

    // =================================================
    // GET — cargar compras
    // =================================================

    if (request.method === "GET") {

      const [
        purchasesResult,
        itemsResult,
        lotsResult
      ] = await env.DB.batch([

        env.DB.prepare(`
          SELECT
            p.id,
            p.doc_type,
            p.doc_number,
            p.date,
            p.supplier_id,
            s.name AS supplier_name,
            p.created_at,
            p.updated_at
          FROM purchases p
          LEFT JOIN suppliers s
            ON s.id = p.supplier_id
          ORDER BY p.date DESC, p.created_at DESC
        `),

        env.DB.prepare(`
          SELECT
            pi.id,
            pi.purchase_id,
            pi.ingredient_id,
            i.name AS ingredient_name,
            pi.supply_id,
            os.name AS supply_name,
            pi.quantity,
            pi.unit_cost,
            pl.id AS lot_id,
            pi.created_at,
            pi.updated_at
          FROM purchase_items pi
          LEFT JOIN ingredients i
            ON i.id = pi.ingredient_id
          LEFT JOIN other_supplies os
            ON os.id = pi.supply_id
          LEFT JOIN purchase_lots pl
            ON pl.purchase_item_id = pi.id
          ORDER BY pi.purchase_id, pi.id
        `),

        env.DB.prepare(`
          SELECT
            pl.id,
            pl.purchase_item_id,
            pl.quantity_initial,
            pl.quantity_available,
            pl.unit_cost,
            pl.created_at,
            pl.updated_at
          FROM purchase_lots pl
          ORDER BY pl.created_at
        `)

      ]);

      const purchasesRows = purchasesResult.results || [];
      const itemsRows = itemsResult.results || [];
      const lotsRows = lotsResult.results || [];

      const purchases = purchasesRows.map(purchase => {

        const items = itemsRows
          .filter(item => item.purchase_id === purchase.id)
          .map(item => {

            const lot = lotsRows.find(
              l => l.id === item.lot_id
            );

            return {
              id: item.id,

              ingredientId: item.ingredient_id || null,
              ingredientName: item.ingredient_name || "",

              supplyId: item.supply_id || null,
              supplyName: item.supply_name || "",

              qty: Number(item.quantity) || 0,
              unitCost: Number(item.unit_cost) || 0,

              lotId: item.lot_id || null,

              lot: lot ? {
                id: lot.id,
                quantityInitial:
                  Number(lot.quantity_initial) || 0,
                quantityAvailable:
                  Number(lot.quantity_available) || 0,
                unitCost:
                  Number(lot.unit_cost) || 0
              } : null
            };
          });

        return {
          id: purchase.id,
          docType: purchase.doc_type || "",
          docNumber: purchase.doc_number || "",
          date: purchase.date || "",
          supplierId: purchase.supplier_id || null,
          supplierName: purchase.supplier_name || "",
          items
        };
      });

      return json({
        ok: true,
        purchases
      });
    }

    // =================================================
    // POST — guardar cambios
    // =================================================

    if (request.method === "POST") {

      const body = await request.json();
      const { action, data } = body;

      // =================================================
      // CREAR COMPRA
      // =================================================

      if (action === "create") {

        const purchaseId =
          data.id || uidServer("p");

        const items = Array.isArray(data.items)
          ? data.items
          : [];

        const statements = [];

        // Cabecera
        statements.push(
          env.DB.prepare(`
            INSERT INTO purchases
              (
                id,
                doc_type,
                doc_number,
                date,
                supplier_id
              )
            VALUES (?, ?, ?, ?, ?)
          `).bind(
            purchaseId,
            data.docType || "",
            data.docNumber || "",
            data.date || null,
            data.supplierId || null
          )
        );

        // Detalle + lotes
        for (const item of items) {

          const itemId =
            item.id || uidServer("pi");

          const quantity =
            Number(item.qty) || 0;

          const unitCost =
            Number(item.unitCost) || 0;

          const lotId =
            item.lotId || uidServer("lot");

          statements.push(
            env.DB.prepare(`
              INSERT INTO purchase_items
                (
                  id,
                  purchase_id,
                  ingredient_id,
                  supply_id,
                  quantity,
                  unit_cost,
                  lot_id
                )
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(
              itemId,
              purchaseId,
              item.ingredientId || null,
              item.supplyId || null,
              quantity,
              unitCost,
              lotId
            )
          );

          statements.push(
            env.DB.prepare(`
              INSERT INTO purchase_lots
                (
                  id,
                  purchase_item_id,
                  quantity_initial,
                  quantity_available,
                  unit_cost
                )
              VALUES (?, ?, ?, ?, ?)
            `).bind(
              lotId,
              itemId,
              quantity,
              quantity,
              unitCost
            )
          );
        }

        await env.DB.batch(statements);

        return json({
          ok: true,
          id: purchaseId
        });
      }

      // =================================================
      // ACTUALIZAR COMPRA
      // =================================================

      if (action === "update") {

        const purchaseId = data.id;

        const items = Array.isArray(data.items)
          ? data.items
          : [];

        // Primero eliminamos detalle y lotes anteriores.
        // La compra se vuelve a construir con los datos actuales.

        const oldItems =
          await env.DB.prepare(`
            SELECT id
            FROM purchase_items
            WHERE purchase_id = ?
          `).bind(purchaseId).all();

        const statements = [];

        for (const oldItem of oldItems.results || []) {

          statements.push(
            env.DB.prepare(`
              DELETE FROM purchase_lots
              WHERE purchase_item_id = ?
            `).bind(oldItem.id)
          );
        }

        statements.push(
          env.DB.prepare(`
            DELETE FROM purchase_items
            WHERE purchase_id = ?
          `).bind(purchaseId)
        );

        statements.push(
          env.DB.prepare(`
            UPDATE purchases
            SET
              doc_type = ?,
              doc_number = ?,
              date = ?,
              supplier_id = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `).bind(
            data.docType || "",
            data.docNumber || "",
            data.date || null,
            data.supplierId || null,
            purchaseId
          )
        );

        for (const item of items) {

          const itemId =
            item.id || uidServer("pi");

          const quantity =
            Number(item.qty) || 0;

          const unitCost =
            Number(item.unitCost) || 0;

          const lotId =
            item.lotId || uidServer("lot");

          statements.push(
            env.DB.prepare(`
              INSERT INTO purchase_items
                (
                  id,
                  purchase_id,
                  ingredient_id,
                  supply_id,
                  quantity,
                  unit_cost,
                  lot_id
                )
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(
              itemId,
              purchaseId,
              item.ingredientId || null,
              item.supplyId || null,
              quantity,
              unitCost,
              lotId
            )
          );

          statements.push(
            env.DB.prepare(`
              INSERT INTO purchase_lots
                (
                  id,
                  purchase_item_id,
                  quantity_initial,
                  quantity_available,
                  unit_cost
                )
              VALUES (?, ?, ?, ?, ?)
            `).bind(
              lotId,
              itemId,
              quantity,
              quantity,
              unitCost
            )
          );
        }

        await env.DB.batch(statements);

        return json({
          ok: true
        });
      }

      // =================================================
      // ELIMINAR COMPRA
      // =================================================

      if (action === "delete") {

        // Antes de eliminar verificamos si los lotes
        // ya fueron utilizados en retiros.

        const usedLots = await env.DB.prepare(`
          SELECT COUNT(*) AS count
          FROM withdrawal_allocations wa
          INNER JOIN purchase_lots pl
            ON pl.id = wa.lot_id
          INNER JOIN purchase_items pi
            ON pi.id = pl.purchase_item_id
          WHERE pi.purchase_id = ?
        `).bind(data.id).first();

        if (Number(usedLots?.count || 0) > 0) {
          return json({
            ok: false,
            error:
              "No se puede eliminar esta compra porque sus lotes ya fueron utilizados en movimientos de stock."
          }, 400);
        }

        const oldItems =
          await env.DB.prepare(`
            SELECT id
            FROM purchase_items
            WHERE purchase_id = ?
          `).bind(data.id).all();

        const statements = [];

        for (const item of oldItems.results || []) {

          statements.push(
            env.DB.prepare(`
              DELETE FROM purchase_lots
              WHERE purchase_item_id = ?
            `).bind(item.id)
          );
        }

        statements.push(
          env.DB.prepare(`
            DELETE FROM purchase_items
            WHERE purchase_id = ?
          `).bind(data.id)
        );

        statements.push(
          env.DB.prepare(`
            DELETE FROM purchases
            WHERE id = ?
          `).bind(data.id)
        );

        await env.DB.batch(statements);

        return json({
          ok: true
        });
      }

      return json({
        ok: false,
        error: "Acción no reconocida"
      }, 400);
    }

    return json({
      error: "Método no permitido"
    }, 405);

  } catch (error) {

    console.error("Error en compras D1:", error);

    return json({
      ok: false,
      error: error.message
    }, 500);
  }
}
export default {
  async fetch(request, env, ctx) {
    const url = new URL(
      request.url
    );

    if (url.pathname === "/api/setup") {
      return handleSetup(request, env);
    }
    if (url.pathname === "/api/db-test") {
  return handleDbTest(request, env);
}
    if (url.pathname === "/api/catalog") {
  return handleCatalog(request, env);
}
    if (url.pathname === "/api/contacts") {
  return handleContacts(request, env);
}
    if (url.pathname === "/api/orders") {
  return handleOrders(request, env);
}
    if (url.pathname === "/api/purchases") {
  return handlePurchases(request, env);
}

    if (url.pathname === "/api/login") {
      return handleLogin(request, env);
    }

    if (url.pathname === "/api/me") {
      return handleMe(request, env);
    }

    if (url.pathname === "/api/logout") {
      return handleLogout(request, env);
    }

    return env.ASSETS.fetch(
      request
    );
  }
};
