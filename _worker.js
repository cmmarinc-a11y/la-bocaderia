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

  // Permite restablecer la contraseña de un usuario existente
  // usando la misma clave segura de configuración.
  if (existingUser && body.action === "reset-password") {
    const passwordHash =
      await createPasswordHash(password);

    await env.DB.prepare(`
      UPDATE users
      SET password_hash = ?
      WHERE id = ?
    `)
      .bind(passwordHash, existingUser.id)
      .run();

    // Invalidamos sesiones anteriores para que el cambio de contraseña
    // tenga efecto inmediatamente en todos los dispositivos.
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
    `)
      .bind(existingUser.id)
      .run();

    return json({
      ok: true,
      message: "Contraseña actualizada correctamente",
      username
    });
  }

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
function uidServer(prefix = "id") {
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

        const orderNumber = await generateOrderNumber(env);

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
    if (!user) return json({ error: "No autorizado" }, 401);

    if (request.method === "GET") {
      const [purchasesResult, itemsResult, lotsResult] = await env.DB.batch([
        env.DB.prepare(`
          SELECT p.id, p.doc_type, p.doc_number, p.date, p.supplier_id,
                 s.name AS supplier_name, p.created_at, p.updated_at
          FROM purchases p
          LEFT JOIN suppliers s ON s.id = p.supplier_id
          ORDER BY p.date DESC, p.created_at DESC
        `),
        env.DB.prepare(`
          SELECT pi.id, pi.purchase_id, pi.ingredient_id, i.name AS ingredient_name,
                 pi.supply_id, os.name AS supply_name, pi.quantity, pi.unit_cost,
                 pl.id AS lot_id, pl.lot_number, pi.created_at, pi.updated_at
          FROM purchase_items pi
          LEFT JOIN ingredients i ON i.id = pi.ingredient_id
          LEFT JOIN other_supplies os ON os.id = pi.supply_id
          LEFT JOIN purchase_lots pl ON pl.purchase_item_id = pi.id
          ORDER BY pi.purchase_id, pi.id
        `),
        env.DB.prepare(`
          SELECT id, purchase_item_id, quantity_initial, quantity_available,
                 unit_cost, lot_number, created_at, updated_at
          FROM purchase_lots
          ORDER BY created_at
        `)
      ]);

      const purchasesRows = purchasesResult.results || [];
      const itemsRows = itemsResult.results || [];
      const lotsRows = lotsResult.results || [];

      const purchases = purchasesRows.map(purchase => ({
        id: purchase.id,
        docType: purchase.doc_type || "",
        docNumber: purchase.doc_number || "",
        date: purchase.date || "",
        supplierId: purchase.supplier_id || null,
        supplier: purchase.supplier_id || "",
        supplierName: purchase.supplier_name || "",
        lines: itemsRows
          .filter(item => item.purchase_id === purchase.id)
          .map(item => {
            const lot = lotsRows.find(l => l.id === item.lot_id);
            const category = item.ingredient_id ? "ingredient" : "other";
            return {
              id: item.id,
              category,
              item: item.ingredient_name || item.supply_name || "",
              ingredientId: item.ingredient_id || null,
              supplyId: item.supply_id || null,
              ingredientName: item.ingredient_name || "",
              supplyName: item.supply_name || "",
              qty: Number(item.quantity) || 0,
              quantity: Number(item.quantity) || 0,
              cost: (Number(item.quantity) || 0) * (Number(item.unit_cost) || 0),
              unitCost: Number(item.unit_cost) || 0,
              lotId: item.lot_id || null,
              lotNumber: item.lot_number != null ? Number(item.lot_number) : null,
              lot: lot ? {
                id: lot.id,
                lotNumber: lot.lot_number != null ? Number(lot.lot_number) : null,
                quantityInitial: Number(lot.quantity_initial) || 0,
                quantityAvailable: Number(lot.quantity_available) || 0,
                unitCost: Number(lot.unit_cost) || 0
              } : null
            };
          })
      }));

      return json({ ok: true, purchases });
    }

    if (request.method !== "POST") {
      return json({ error: "Método no permitido" }, 405);
    }

    const body = await request.json();
    const { action, data } = body;
    if (!data) return json({ ok: false, error: "Faltan datos de compra" }, 400);

    const items = Array.isArray(data.items) ? data.items : [];
    if (!items.length) return json({ ok: false, error: "La compra debe tener al menos un producto" }, 400);

    if (action === "create") {
      const purchaseId = data.id || uidServer("p");
      const statements = [
        env.DB.prepare(`
          INSERT INTO purchases (id, doc_type, doc_number, date, supplier_id)
          VALUES (?, ?, ?, ?, ?)
        `).bind(
          purchaseId,
          data.docType || "",
          data.docNumber || "",
          data.date || null,
          data.supplierId || null
        )
      ];

      const lotCounterRow = await env.DB.prepare(`
        SELECT COALESCE(MAX(lot_number), 0) AS max_lot_number
        FROM purchase_lots
      `).first();

      let nextLotNumber = Number(lotCounterRow?.max_lot_number || 0) + 1;

      for (const item of items) {
        const itemId = item.id || uidServer("pi");
        const quantity = Number(item.qty ?? item.quantity) || 0;
        const unitCost = Number(item.unitCost ?? (quantity ? Number(item.cost || 0) / quantity : 0)) || 0;
        if (quantity <= 0 || unitCost < 0) {
          return json({ ok: false, error: "Cantidad o costo inválido en la compra" }, 400);
        }

        const lotId = item.lotId || uidServer("lot");
        const lotNumber = nextLotNumber++;
        const ingredientId = item.ingredientId || null;
        const supplyId = item.supplyId || null;

        if (!ingredientId && !supplyId) {
          return json({ ok: false, error: "Cada línea debe indicar un ingrediente o un insumo" }, 400);
        }

        statements.push(
          env.DB.prepare(`
            INSERT INTO purchase_items
              (id, purchase_id, ingredient_id, supply_id, quantity, unit_cost)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(itemId, purchaseId, ingredientId, supplyId, quantity, unitCost)
        );

        statements.push(
          env.DB.prepare(`
            INSERT INTO purchase_lots
              (id, purchase_item_id, quantity_initial, quantity_available, unit_cost, lot_number)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(lotId, itemId, quantity, quantity, unitCost, lotNumber)
        );

        statements.push(
          env.DB.prepare(`
            INSERT INTO movements
              (id, date, type, ingredient_id, supply_id, quantity, unit_cost, total_cost, reference_id)
            VALUES (?, ?, 'purchase', ?, ?, ?, ?, ?, ?)
          `).bind(
            uidServer("movement"),
            data.date || new Date().toISOString(),
            ingredientId,
            supplyId,
            quantity,
            unitCost,
            quantity * unitCost,
            purchaseId
          )
        );
      }

      await env.DB.batch(statements);
      return json({ ok: true, id: purchaseId });
    }

    if (action === "update") {
      const purchaseId = data.id;
      if (!purchaseId) return json({ ok: false, error: "Falta el ID de la compra" }, 400);

      const used = await env.DB.prepare(`
        SELECT COUNT(*) AS count
        FROM purchase_lots pl
        LEFT JOIN withdrawal_allocations wa ON wa.lot_id = pl.id
        WHERE pl.purchase_item_id IN (
          SELECT id FROM purchase_items WHERE purchase_id = ?
        )
        AND (
          pl.quantity_available < pl.quantity_initial
          OR wa.id IS NOT NULL
        )
      `).bind(purchaseId).first();

      if (Number(used?.count || 0) > 0) {
        return json({
          ok: false,
          error: "No se puede editar esta compra porque uno o más lotes ya fueron utilizados en movimientos de stock."
        }, 400);
      }

      const oldItems = await env.DB.prepare(`
        SELECT id FROM purchase_items WHERE purchase_id = ?
      `).bind(purchaseId).all();

      const statements = [];
      statements.push(
        env.DB.prepare(`DELETE FROM movements WHERE type = 'purchase' AND reference_id = ?`).bind(purchaseId)
      );
      for (const oldItem of oldItems.results || []) {
        statements.push(
          env.DB.prepare(`DELETE FROM purchase_lots WHERE purchase_item_id = ?`).bind(oldItem.id)
        );
      }
      statements.push(
        env.DB.prepare(`DELETE FROM purchase_items WHERE purchase_id = ?`).bind(purchaseId)
      );
      statements.push(
        env.DB.prepare(`
          UPDATE purchases
          SET doc_type = ?, doc_number = ?, date = ?, supplier_id = ?,
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

      const lotCounterRow = await env.DB.prepare(`
        SELECT COALESCE(MAX(lot_number), 0) AS max_lot_number
        FROM purchase_lots
      `).first();

      let nextLotNumber = Number(lotCounterRow?.max_lot_number || 0) + 1;

      for (const item of items) {
        const itemId = item.id || uidServer("pi");
        const quantity = Number(item.qty ?? item.quantity) || 0;
        const unitCost = Number(item.unitCost ?? (quantity ? Number(item.cost || 0) / quantity : 0)) || 0;
        const lotId = item.lotId || uidServer("lot");
        const lotNumber = nextLotNumber++;
        const ingredientId = item.ingredientId || null;
        const supplyId = item.supplyId || null;

        statements.push(
          env.DB.prepare(`
            INSERT INTO purchase_items
              (id, purchase_id, ingredient_id, supply_id, quantity, unit_cost)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(itemId, purchaseId, ingredientId, supplyId, quantity, unitCost)
        );
        statements.push(
          env.DB.prepare(`
            INSERT INTO purchase_lots
              (id, purchase_item_id, quantity_initial, quantity_available, unit_cost, lot_number)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(lotId, itemId, quantity, quantity, unitCost, lotNumber)
        );
        statements.push(
          env.DB.prepare(`
            INSERT INTO movements
              (id, date, type, ingredient_id, supply_id, quantity, unit_cost, total_cost, reference_id)
            VALUES (?, ?, 'purchase', ?, ?, ?, ?, ?, ?)
          `).bind(
            uidServer("movement"),
            data.date || new Date().toISOString(),
            ingredientId,
            supplyId,
            quantity,
            unitCost,
            quantity * unitCost,
            purchaseId
          )
        );
      }

      await env.DB.batch(statements);
      return json({ ok: true });
    }

    if (action === "delete") {
      const purchaseId = data.id;
      const used = await env.DB.prepare(`
        SELECT COUNT(*) AS count
        FROM purchase_lots pl
        LEFT JOIN withdrawal_allocations wa ON wa.lot_id = pl.id
        WHERE pl.purchase_item_id IN (
          SELECT id FROM purchase_items WHERE purchase_id = ?
        )
        AND (
          pl.quantity_available < pl.quantity_initial
          OR wa.id IS NOT NULL
        )
      `).bind(purchaseId).first();

      if (Number(used?.count || 0) > 0) {
        return json({
          ok: false,
          error: "No se puede eliminar esta compra porque sus lotes ya fueron utilizados en movimientos de stock."
        }, 400);
      }

      const oldItems = await env.DB.prepare(`
        SELECT id FROM purchase_items WHERE purchase_id = ?
      `).bind(purchaseId).all();

      const statements = [
        env.DB.prepare(`DELETE FROM movements WHERE type = 'purchase' AND reference_id = ?`).bind(purchaseId)
      ];
      for (const oldItem of oldItems.results || []) {
        statements.push(env.DB.prepare(`DELETE FROM purchase_lots WHERE purchase_item_id = ?`).bind(oldItem.id));
      }
      statements.push(env.DB.prepare(`DELETE FROM purchase_items WHERE purchase_id = ?`).bind(purchaseId));
      statements.push(env.DB.prepare(`DELETE FROM purchases WHERE id = ?`).bind(purchaseId));

      await env.DB.batch(statements);
      return json({ ok: true });
    }

    return json({ ok: false, error: "Acción no reconocida" }, 400);
  } catch (error) {
    console.error("Error en compras D1:", error);
    return json({ ok: false, error: error.message }, 500);
  }
}
// =====================================================
// D1 — PRODUCCIÓN
// =====================================================

async function handleProduction(request, env) {
  try {
    const user = await getSessionUser(request, env);
    if (!user) return json({ error: "No autorizado" }, 401);

    if (request.method === "GET") {
      const [productionResult, itemsResult, ingredientsResult, suppliesResult] = await env.DB.batch([
        env.DB.prepare(`
          SELECT p.id, p.order_id, o.number AS order_number, p.date,
                 p.sale, p.cost, p.gain, p.margin, p.created_at, p.updated_at
          FROM production p
          LEFT JOIN orders o ON o.id = p.order_id
          ORDER BY p.date DESC, p.created_at DESC
        `),
        env.DB.prepare(`
          SELECT pi.id, pi.production_id, pi.recipe_id, r.name AS recipe_name,
                 pi.quantity, r.sale_price AS unit_price,
                 (pi.quantity * r.sale_price) AS subtotal
          FROM production_items pi
          LEFT JOIN recipes r ON r.id = pi.recipe_id
          ORDER BY pi.production_id, pi.id
        `),
        env.DB.prepare(`
          SELECT pgi.id, pgi.production_id, pgi.ingredient_id,
                 i.name AS ingredient_name, pgi.quantity, pgi.unit_cost,
                 pgi.total_cost AS subtotal
          FROM production_ingredients pgi
          LEFT JOIN ingredients i ON i.id = pgi.ingredient_id
          ORDER BY pgi.production_id, pgi.id
        `),
        env.DB.prepare(`
          SELECT pgs.id, pgs.production_id, pgs.supply_id,
                 os.name AS supply_name, pgs.quantity, pgs.unit_cost,
                 pgs.total_cost AS subtotal
          FROM production_supplies pgs
          LEFT JOIN other_supplies os ON os.id = pgs.supply_id
          ORDER BY pgs.production_id, pgs.id
        `)
      ]);

      const productionRows = productionResult.results || [];
      const itemRows = itemsResult.results || [];
      const ingredientRows = ingredientsResult.results || [];
      const supplyRows = suppliesResult.results || [];

      const production = productionRows.map(p => ({
        id: p.id,
        orderId: p.order_id,
        orderNumber: p.order_number || "",
        date: p.date,
        sale: Number(p.sale) || 0,
        cost: Number(p.cost) || 0,
        gain: Number(p.gain) || 0,
        margin: Number(p.margin) || 0,
        items: itemRows.filter(x => x.production_id === p.id).map(x => ({
          id: x.id,
          recipeId: x.recipe_id,
          product: x.recipe_name || "",
          qty: Number(x.quantity) || 0,
          unitPrice: Number(x.unit_price) || 0,
          subtotal: Number(x.subtotal) || 0
        })),
        ingredients: ingredientRows.filter(x => x.production_id === p.id).map(x => ({
          id: x.id,
          ingredientId: x.ingredient_id,
          ingredient: x.ingredient_name || "",
          quantity: Number(x.quantity) || 0,
          unitCost: Number(x.unit_cost) || 0,
          subtotal: Number(x.subtotal) || 0
        })),
        supplies: supplyRows.filter(x => x.production_id === p.id).map(x => ({
          id: x.id,
          supplyId: x.supply_id,
          supply: x.supply_name || "",
          quantity: Number(x.quantity) || 0,
          unitCost: Number(x.unit_cost) || 0,
          subtotal: Number(x.subtotal) || 0
        }))
      }));

      return json({ ok: true, production });
    }

    if (request.method !== "POST") {
      return json({ error: "Método no permitido" }, 405);
    }

    const body = await request.json();
    const { action, data } = body;

    if (action === "create") {
      const productionId = data.id || uidServer("prod");
      const items = Array.isArray(data.items) ? data.items : [];
      const ingredients = Array.isArray(data.ingredients) ? data.ingredients : [];
      const supplies = Array.isArray(data.supplies) ? data.supplies : [];

      if (!data.orderId) return json({ ok: false, error: "Falta el pedido asociado" }, 400);
      if (!ingredients.length && !supplies.length) {
        return json({ ok: false, error: "La producción no tiene consumos registrados" }, 400);
      }

      const order = await env.DB.prepare(`
        SELECT id, status FROM orders WHERE id = ?
      `).bind(data.orderId).first();

      if (!order) return json({ ok: false, error: "Pedido no encontrado" }, 404);
      if (order.status !== "Preparación") {
        return json({ ok: false, error: "El pedido debe estar en Preparación para registrarlo como producido" }, 400);
      }

      const lotCache = new Map();
      async function loadLots(category, itemId) {
        const key = category + ":" + itemId;
        if (lotCache.has(key)) return lotCache.get(key);
        const lots = await getAvailableLots(env, category, itemId);
        const normalized = lots.map(l => ({
          lotId: String(l.lot_id),
          available: Number(l.quantity_available) || 0,
          unitCost: Number(l.unit_cost) || 0
        }));
        lotCache.set(key, normalized);
        return normalized;
      }

      async function allocate(category, itemId, quantity) {
        let remaining = Number(quantity) || 0;
        if (remaining <= 0) return { allocations: [], totalCost: 0 };

        const lots = await loadLots(category, itemId);
        const allocations = [];
        let totalCost = 0;

        for (const lot of lots) {
          if (remaining <= 0.000001) break;
          const take = Math.min(lot.available, remaining);
          if (take > 0) {
            allocations.push({
              lotId: lot.lotId,
              quantity: take,
              unitCost: lot.unitCost,
              totalCost: take * lot.unitCost
            });
            lot.available -= take;
            remaining -= take;
            totalCost += take * lot.unitCost;
          }
        }

        if (remaining > 0.000001) {
          throw new Error("Stock insuficiente para completar la producción.");
        }

        return { allocations, totalCost };
      }

      const normalizedIngredients = [];
      const normalizedSupplies = [];
      const lotUpdates = [];
      const movementStatements = [];
      let totalCost = 0;

      for (const item of ingredients) {
        const quantity = Number(item.quantity) || 0;
        if (quantity <= 0) continue;
        const result = await allocate("ingredient", item.ingredientId, quantity);
        const unitCost = quantity ? result.totalCost / quantity : 0;
        normalizedIngredients.push({
          id: item.id || uidServer("prod-ingredient"),
          ingredientId: item.ingredientId,
          quantity,
          unitCost,
          totalCost: result.totalCost
        });
        totalCost += result.totalCost;
        for (const a of result.allocations) {
          lotUpdates.push(
            env.DB.prepare(`
              UPDATE purchase_lots
              SET quantity_available = quantity_available - ?, updated_at = CURRENT_TIMESTAMP
              WHERE id = ? AND quantity_available >= ?
            `).bind(a.quantity, a.lotId, a.quantity)
          );
        }
        movementStatements.push(
          env.DB.prepare(`
            INSERT INTO movements
              (id, date, type, ingredient_id, supply_id, quantity, unit_cost, total_cost, reference_id)
            VALUES (?, ?, 'production', ?, NULL, ?, ?, ?, ?)
          `).bind(
            uidServer("movement"),
            data.date || new Date().toISOString(),
            item.ingredientId,
            quantity,
            unitCost,
            result.totalCost,
            productionId
          )
        );
      }

      for (const item of supplies) {
        const quantity = Number(item.quantity) || 0;
        if (quantity <= 0) continue;
        const result = await allocate("other", item.supplyId, quantity);
        const unitCost = quantity ? result.totalCost / quantity : 0;
        normalizedSupplies.push({
          id: item.id || uidServer("prod-supply"),
          supplyId: item.supplyId,
          quantity,
          unitCost,
          totalCost: result.totalCost
        });
        totalCost += result.totalCost;
        for (const a of result.allocations) {
          lotUpdates.push(
            env.DB.prepare(`
              UPDATE purchase_lots
              SET quantity_available = quantity_available - ?, updated_at = CURRENT_TIMESTAMP
              WHERE id = ? AND quantity_available >= ?
            `).bind(a.quantity, a.lotId, a.quantity)
          );
        }
        movementStatements.push(
          env.DB.prepare(`
            INSERT INTO movements
              (id, date, type, ingredient_id, supply_id, quantity, unit_cost, total_cost, reference_id)
            VALUES (?, ?, 'production', NULL, ?, ?, ?, ?, ?)
          `).bind(
            uidServer("movement"),
            data.date || new Date().toISOString(),
            item.supplyId,
            quantity,
            unitCost,
            result.totalCost,
            productionId
          )
        );
      }

      const saleFromItems = items.reduce(
        (sum, item) => sum + (Number(item.subtotal) || ((Number(item.qty) || 0) * (Number(item.unitPrice) || 0))),
        0
      );
      const sale = Number(data.sale) || saleFromItems;
      const gain = sale - totalCost;
      const margin = sale > 0 ? gain / sale : 0;

      const statements = [
        env.DB.prepare(`
          INSERT INTO production
            (id, order_id, date, sale, cost, gain, margin)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          productionId,
          data.orderId,
          data.date || new Date().toISOString(),
          sale,
          totalCost,
          gain,
          margin
        )
      ];

      for (const item of items) {
        const quantity = Number(item.qty) || 0;
        if (quantity <= 0) continue;
        statements.push(
          env.DB.prepare(`
            INSERT INTO production_items
              (id, production_id, recipe_id, quantity)
            VALUES (?, ?, ?, ?)
          `).bind(
            item.id || uidServer("prod-item"),
            productionId,
            item.recipeId || null,
            quantity
          )
        );
      }

      for (const item of normalizedIngredients) {
        statements.push(
          env.DB.prepare(`
            INSERT INTO production_ingredients
              (id, production_id, ingredient_id, quantity, unit_cost, total_cost)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(
            item.id,
            productionId,
            item.ingredientId,
            item.quantity,
            item.unitCost,
            item.totalCost
          )
        );
      }

      for (const item of normalizedSupplies) {
        statements.push(
          env.DB.prepare(`
            INSERT INTO production_supplies
              (id, production_id, supply_id, quantity, unit_cost, total_cost)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(
            item.id,
            productionId,
            item.supplyId,
            item.quantity,
            item.unitCost,
            item.totalCost
          )
        );
      }

      statements.push(
        env.DB.prepare(`
          UPDATE orders
          SET status = 'Preparado', updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(data.orderId)
      );

      statements.push(...lotUpdates, ...movementStatements);

      await env.DB.batch(statements);

      return json({
        ok: true,
        id: productionId,
        sale,
        cost: totalCost,
        gain,
        margin
      });
    }

    if (action === "update" || action === "delete") {
      return json({
        ok: false,
        error: "La producción registrada no se puede editar ni eliminar desde este flujo."
      }, 400);
    }

    return json({ ok: false, error: "Acción no reconocida" }, 400);
  } catch (error) {
    console.error("Error en producción D1:", error);
    return json({ ok: false, error: error.message }, 500);
  }
}
// ============================================================
// BLOQUE 6 — STOCK Y MOVIMIENTOS
// ============================================================


function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}


// ------------------------------------------------------------
// GET STOCK
// ------------------------------------------------------------

async function handleStock(request, env) {
  try {
    const user = await getSessionUser(request, env);
    if (!user) return json({ error: "No autorizado" }, 401);

    const url = new URL(request.url);
    const category = url.searchParams.get("category");
    const itemId = url.searchParams.get("itemId");

    if (category && itemId) {
      const excludeWithdrawalId = url.searchParams.get("excludeWithdrawalId");
      const lots = await getAvailableLots(env, category, itemId);

      if (excludeWithdrawalId) {
        const old = await env.DB.prepare(`
          SELECT wa.lot_id, wa.quantity,
                 pl.purchase_item_id,
                 pl.quantity_available, pl.quantity_initial, pl.unit_cost,
                 pl.lot_number,
                 p.date AS purchase_date
          FROM withdrawal_allocations wa
          JOIN purchase_lots pl ON pl.id = wa.lot_id
          JOIN purchase_items pi ON pi.id = pl.purchase_item_id
          JOIN purchases p ON p.id = pi.purchase_id
          WHERE wa.withdrawal_id = ?
            AND (
              (? = 'ingredient' AND pi.ingredient_id = ?)
              OR
              (? = 'other' AND pi.supply_id = ?)
            )
        `).bind(
          excludeWithdrawalId,
          category, itemId,
          category, itemId
        ).all();

        const map = new Map(lots.map(l => [String(l.lot_id), {
          lot_id:String(l.lot_id),
          purchase_item_id:l.purchase_item_id,
          quantity_initial:Number(l.quantity_initial)||0,
          quantity_available:Number(l.quantity_available)||0,
          unit_cost:Number(l.unit_cost)||0,
          lot_number:l.lot_number != null ? Number(l.lot_number) : null,
          purchase_date:l.purchase_date
        }]));

        for (const row of old.results || []) {
          const key=String(row.lot_id);
          if (map.has(key)) {
            map.get(key).quantity_available += Number(row.quantity)||0;
          } else {
            map.set(key,{
              lot_id:key,
              purchase_item_id:row.purchase_item_id,
              quantity_initial:Number(row.quantity_initial)||0,
              quantity_available:(Number(row.quantity_available)||0)+(Number(row.quantity)||0),
              unit_cost:Number(row.unit_cost)||0,
              lot_number:row.lot_number != null ? Number(row.lot_number) : null,
              purchase_date:row.purchase_date
            });
          }
        }

        return json({ ok:true, lots:Array.from(map.values()).filter(l=>l.quantity_available>0) });
      }

      return json({ ok: true, lots });
    }

    const [ingredients, otherSupplies] = await Promise.all([
      env.DB.prepare(`
        SELECT
          i.id, i.name, i.unit, i.status,
          COALESCE(SUM(pl.quantity_available), 0) AS stock,
          COALESCE((
            SELECT pl2.unit_cost
            FROM purchase_lots pl2
            JOIN purchase_items pi2 ON pi2.id = pl2.purchase_item_id
            WHERE pi2.ingredient_id = i.id
              AND pl2.quantity_available > 0
            ORDER BY pl2.created_at ASC
            LIMIT 1
          ), 0) AS unit_cost
        FROM ingredients i
        LEFT JOIN purchase_items pi ON pi.ingredient_id = i.id
        LEFT JOIN purchase_lots pl ON pl.purchase_item_id = pi.id
        GROUP BY i.id, i.name, i.unit, i.status
        ORDER BY i.name ASC
      `).all(),
      env.DB.prepare(`
        SELECT
          os.id, os.name, os.unit, os.consumable, os.status,
          COALESCE(SUM(pl.quantity_available), 0) AS stock,
          COALESCE((
            SELECT pl2.unit_cost
            FROM purchase_lots pl2
            JOIN purchase_items pi2 ON pi2.id = pl2.purchase_item_id
            WHERE pi2.supply_id = os.id
              AND pl2.quantity_available > 0
            ORDER BY pl2.created_at ASC
            LIMIT 1
          ), 0) AS unit_cost
        FROM other_supplies os
        LEFT JOIN purchase_items pi ON pi.supply_id = os.id
        LEFT JOIN purchase_lots pl ON pl.purchase_item_id = pi.id
        GROUP BY os.id, os.name, os.unit, os.consumable, os.status
        ORDER BY os.name ASC
      `).all()
    ]);

    return json({
      ok: true,
      ingredients: ingredients.results || [],
      otherSupplies: otherSupplies.results || []
    });
  } catch (error) {
    return json({ ok: false, error: String(error) }, 500);
  }
}


// ------------------------------------------------------------
// GET MOVEMENTS
// ------------------------------------------------------------

async function handleMovements(request, env) {
  try {
    const user = await getSessionUser(request, env);
    if (!user) return json({ error: "No autorizado" }, 401);

    const result = await env.DB.prepare(`
      SELECT
        m.id, m.date, m.type,
        m.ingredient_id, i.name AS ingredient_name,
        m.supply_id, os.name AS supply_name,
        m.quantity, m.unit_cost, m.total_cost,
        m.reference_id, m.created_at
      FROM movements m
      LEFT JOIN ingredients i ON i.id = m.ingredient_id
      LEFT JOIN other_supplies os ON os.id = m.supply_id
      ORDER BY m.date DESC, m.created_at DESC
    `).all();

    return json({ ok: true, movements: result.results || [] });
  } catch (error) {
    return json({ ok: false, error: String(error) }, 500);
  }
}


// ------------------------------------------------------------
// GET WITHDRAWALS
// ------------------------------------------------------------

async function handleWithdrawals(request, env) {
  try {
    const user = await getSessionUser(request, env);
    if (!user) return json({ error: "No autorizado" }, 401);

    const [withdrawals, allocations] = await env.DB.batch([
      env.DB.prepare(`
        SELECT
          w.id, w.date, w.ingredient_id, i.name AS ingredient_name,
          w.supply_id, os.name AS supply_name,
          w.quantity, w.reason, w.note, w.created_at, w.updated_at
        FROM withdrawals w
        LEFT JOIN ingredients i ON i.id = w.ingredient_id
        LEFT JOIN other_supplies os ON os.id = w.supply_id
        ORDER BY w.date DESC, w.created_at DESC
      `),
      env.DB.prepare(`
        SELECT
          wa.id, wa.withdrawal_id, wa.lot_id, pl.lot_number,
          wa.quantity, wa.unit_cost, wa.total_cost, wa.created_at
        FROM withdrawal_allocations wa
        LEFT JOIN purchase_lots pl ON pl.id = wa.lot_id
        ORDER BY wa.withdrawal_id, wa.created_at
      `)
    ]);

    return json({
      ok: true,
      withdrawals: withdrawals.results || [],
      allocations: allocations.results || []
    });
  } catch (error) {
    return json({ ok: false, error: String(error) }, 500);
  }
}


// ------------------------------------------------------------
// GET AVAILABLE LOTS
// ------------------------------------------------------------

async function getAvailableLots(env, category, itemId) {
  let query;
  let params;

  if (category === "ingredient") {
    query = `
      SELECT
        pl.id AS lot_id,
        pl.purchase_item_id,
        pl.quantity_initial,
        pl.quantity_available,
        pl.unit_cost,
        pl.lot_number,
        p.date AS purchase_date
      FROM purchase_lots pl
      JOIN purchase_items pi
        ON pi.id = pl.purchase_item_id
      JOIN purchases p
        ON p.id = pi.purchase_id
      WHERE pi.ingredient_id = ?
        AND pl.quantity_available > 0
      ORDER BY p.date ASC, pl.created_at ASC
    `;
    params = [itemId];

  } else if (category === "other") {
    query = `
      SELECT
        pl.id AS lot_id,
        pl.purchase_item_id,
        pl.quantity_initial,
        pl.quantity_available,
        pl.unit_cost,
        pl.lot_number,
        p.date AS purchase_date
      FROM purchase_lots pl
      JOIN purchase_items pi
        ON pi.id = pl.purchase_item_id
      JOIN purchases p
        ON p.id = pi.purchase_id
      WHERE pi.supply_id = ?
        AND pl.quantity_available > 0
      ORDER BY p.date ASC, pl.created_at ASC
    `;
    params = [itemId];

  } else {
    throw new Error("Categoría inválida");
  }

  const result = await env.DB
    .prepare(query)
    .bind(...params)
    .all();

  return result.results || [];
}


// ------------------------------------------------------------
// CREATE WITHDRAWAL
// ------------------------------------------------------------

async function createWithdrawal(request, env) {
  const body = await request.json();

  const {
    id,
    date,
    category,
    itemId,
    quantity,
    reason,
    note,
    allocations
  } = body;

  if (!category || !itemId) {
    return json({
      ok: false,
      error: "Falta categoría o producto"
    }, 400);
  }

  const totalQuantity = num(quantity);

  if (totalQuantity <= 0) {
    return json({
      ok: false,
      error: "La cantidad debe ser mayor que cero"
    }, 400);
  }

  if (!Array.isArray(allocations) || allocations.length === 0) {
    return json({
      ok: false,
      error: "Debes asignar el retiro a uno o más lotes"
    }, 400);
  }

  const withdrawalId = id || uidServer("withdrawal");

  const ingredientId =
    category === "ingredient" ? itemId : null;

  const supplyId =
    category === "other" ? itemId : null;

  // ----------------------------------------------------------
  // Validar que las asignaciones sumen exactamente el retiro
  // ----------------------------------------------------------

  const allocationQuantity = allocations.reduce(
    (sum, a) => sum + num(a.quantity),
    0
  );

  if (Math.abs(allocationQuantity - totalQuantity) > 0.000001) {
    return json({
      ok: false,
      error: "La cantidad asignada a los lotes no coincide con la cantidad retirada"
    }, 400);
  }

  // ----------------------------------------------------------
  // Obtener lotes actuales
  // ----------------------------------------------------------

  const lots = await getAvailableLots(env, category, itemId);

  const lotMap = new Map(
    lots.map(lot => [String(lot.lot_id), lot])
  );

  let totalCost = 0;

  const normalizedAllocations = [];

  for (const allocation of allocations) {
    const lotId = String(allocation.lotId || "");
    const qty = num(allocation.quantity);

    if (!lotId || qty <= 0) {
      return json({
        ok: false,
        error: "Existe una asignación de lote inválida"
      }, 400);
    }

    const lot = lotMap.get(lotId);

    if (!lot) {
      return json({
        ok: false,
        error: `El lote ${lotId} no existe o ya no tiene stock disponible`
      }, 400);
    }

    if (qty > num(lot.quantity_available) + 0.000001) {
      return json({
        ok: false,
        error: `Stock insuficiente en el lote ${lotId}`
      }, 400);
    }

    const unitCost = num(lot.unit_cost);
    const allocationCost = qty * unitCost;

    totalCost += allocationCost;

    normalizedAllocations.push({
      lotId,
      lotNumber: lot.lot_number != null ? Number(lot.lot_number) : null,
      quantity: qty,
      unitCost,
      totalCost: allocationCost
    });
  }

  // ----------------------------------------------------------
  // Guardar todo en una sola operación
  // ----------------------------------------------------------

  const statements = [];

  statements.push(
    env.DB.prepare(`
      INSERT INTO withdrawals
      (
        id,
        date,
        ingredient_id,
        supply_id,
        quantity,
        reason,
        note
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      withdrawalId,
      date || new Date().toISOString(),
      ingredientId,
      supplyId,
      totalQuantity,
      reason || "",
      note || null
    )
  );

  for (const allocation of normalizedAllocations) {

    statements.push(
      env.DB.prepare(`
        UPDATE purchase_lots
        SET
          quantity_available = quantity_available - ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND quantity_available >= ?
      `).bind(
        allocation.quantity,
        allocation.lotId,
        allocation.quantity
      )
    );

    statements.push(
      env.DB.prepare(`
        INSERT INTO withdrawal_allocations
        (
          id,
          withdrawal_id,
          lot_id,
          quantity,
          unit_cost,
          total_cost
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        uidServer("withdrawal-allocation"),
        withdrawalId,
        allocation.lotId,
        allocation.quantity,
        allocation.unitCost,
        allocation.totalCost
      )
    );
  }

  statements.push(
    env.DB.prepare(`
      INSERT INTO movements
      (
        id,
        date,
        type,
        ingredient_id,
        supply_id,
        quantity,
        unit_cost,
        total_cost,
        reference_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      uidServer("movement"),
      date || new Date().toISOString(),
      "withdrawal",
      ingredientId,
      supplyId,
      totalQuantity,
      totalQuantity > 0 ? totalCost / totalQuantity : 0,
      totalCost,
      withdrawalId
    )
  );

  await env.DB.batch(statements);

  return json({
    ok: true,
    withdrawal: {
      id: withdrawalId,
      date: date || new Date().toISOString(),
      category,
      itemId,
      quantity: totalQuantity,
      reason: reason || "",
      note: note || null,
      totalCost,
      allocations: normalizedAllocations
    }
  });
}


// ------------------------------------------------------------
// UPDATE WITHDRAWAL
// ------------------------------------------------------------

async function updateWithdrawal(request, env) {
  const body = await request.json();
  const { id, date, category, itemId, quantity, reason, note, allocations } = body;

  if (!id) return json({ ok:false, error:"Falta el ID del retiro" }, 400);

  const current = await env.DB.prepare(`
    SELECT * FROM withdrawals WHERE id = ?
  `).bind(id).first();
  if (!current) return json({ ok:false, error:"Retiro no encontrado" }, 404);

  const oldAllocations = await env.DB.prepare(`
    SELECT * FROM withdrawal_allocations WHERE withdrawal_id = ?
  `).bind(id).all();

  const totalQuantity = num(quantity);
  if (totalQuantity <= 0) return json({ ok:false, error:"La cantidad debe ser mayor que cero" }, 400);
  if (!Array.isArray(allocations) || !allocations.length) {
    return json({ ok:false, error:"Debes asignar el retiro a uno o más lotes" }, 400);
  }

  const allocationQuantity = allocations.reduce((sum,a)=>sum+num(a.quantity),0);
  if (Math.abs(allocationQuantity-totalQuantity)>0.000001) {
    return json({ ok:false, error:"La cantidad asignada a los lotes no coincide con la cantidad retirada" },400);
  }

  const lots = await getAvailableLots(env, category, itemId);
  const lotMap = new Map(lots.map(l=>[String(l.lot_id),{
    ...l,
    quantity_available:num(l.quantity_available)
  }]));

  // Para editar, el stock del retiro anterior se considera temporalmente disponible.
  for (const old of oldAllocations.results || []) {
    const key=String(old.lot_id);
    if (lotMap.has(key)) {
      lotMap.get(key).quantity_available += num(old.quantity);
    } else {
      const lot=await env.DB.prepare(`
        SELECT pl.id AS lot_id, pl.purchase_item_id, pl.quantity_initial,
               pl.quantity_available, pl.unit_cost, pl.lot_number,
               p.date AS purchase_date
        FROM purchase_lots pl
        JOIN purchase_items pi ON pi.id = pl.purchase_item_id
        JOIN purchases p ON p.id = pi.purchase_id
        WHERE pl.id = ?
      `).bind(old.lot_id).first();
      if(lot){
        lotMap.set(key,{
          ...lot,
          quantity_available:num(lot.quantity_available)+num(old.quantity)
        });
      }
    }
  }

  let totalCost=0;
  const normalizedAllocations=[];

  for(const allocation of allocations){
    const lotId=String(allocation.lotId||"");
    const qty=num(allocation.quantity);
    if(!lotId||qty<=0)return json({ok:false,error:"Existe una asignación de lote inválida"},400);

    const lot=lotMap.get(lotId);
    if(!lot)return json({ok:false,error:`El lote ${lotId} no existe o ya no tiene stock disponible`},400);
    if(qty>num(lot.quantity_available)+0.000001){
      return json({ok:false,error:`Stock insuficiente en el lote ${lotId}`},400);
    }

    const unitCost=num(lot.unit_cost);
    const allocationCost=qty*unitCost;
    totalCost+=allocationCost;
    normalizedAllocations.push({
      lotId,
      lotNumber: lot.lot_number != null ? Number(lot.lot_number) : null,
      quantity: qty,
      unitCost,
      totalCost: allocationCost
    });
  }

  const statements=[];

  for(const old of oldAllocations.results || []){
    statements.push(
      env.DB.prepare(`
        UPDATE purchase_lots
        SET quantity_available = quantity_available + ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(num(old.quantity),old.lot_id)
    );
  }

  statements.push(
    env.DB.prepare(`DELETE FROM withdrawal_allocations WHERE withdrawal_id = ?`).bind(id),
    env.DB.prepare(`
      DELETE FROM movements
      WHERE type = 'withdrawal' AND reference_id = ?
    `).bind(id),
    env.DB.prepare(`
      UPDATE withdrawals
      SET date = ?, ingredient_id = ?, supply_id = ?, quantity = ?,
          reason = ?, note = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      date || current.date,
      category === "ingredient" ? itemId : null,
      category === "other" ? itemId : null,
      totalQuantity,
      reason || "",
      note || null,
      id
    )
  );

  for(const allocation of normalizedAllocations){
    statements.push(
      env.DB.prepare(`
        UPDATE purchase_lots
        SET quantity_available = quantity_available - ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND quantity_available >= ?
      `).bind(allocation.quantity,allocation.lotId,allocation.quantity),
      env.DB.prepare(`
        INSERT INTO withdrawal_allocations
          (id, withdrawal_id, lot_id, quantity, unit_cost, total_cost)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        uidServer("withdrawal-allocation"),
        id,
        allocation.lotId,
        allocation.quantity,
        allocation.unitCost,
        allocation.totalCost
      )
    );
  }

  statements.push(
    env.DB.prepare(`
      INSERT INTO movements
        (id, date, type, ingredient_id, supply_id, quantity, unit_cost, total_cost, reference_id)
      VALUES (?, ?, 'withdrawal', ?, ?, ?, ?, ?, ?)
    `).bind(
      uidServer("movement"),
      date || current.date,
      category === "ingredient" ? itemId : null,
      category === "other" ? itemId : null,
      totalQuantity,
      totalQuantity ? totalCost/totalQuantity : 0,
      totalCost,
      id
    )
  );

  await env.DB.batch(statements);
  return json({ok:true,id,totalCost});
}


// ------------------------------------------------------------
// ROUTER DEL BLOQUE 6
// ------------------------------------------------------------

async function handleStockApi(request, env) {

  const url = new URL(request.url);

  if (request.method === "GET") {
    return handleStock(request, env);
  }

  return json({
    ok: false,
    error: "Método no permitido"
  }, 405);
}


async function handleWithdrawalsApi(request, env) {

  if (request.method === "GET") {
    return handleWithdrawals(request, env);
  }

  if (request.method !== "POST") {
    return json({
      ok: false,
      error: "Método no permitido"
    }, 405);
  }

  const body = await request.clone().json();

  if (body.action === "update") {
    return updateWithdrawal(request, env);
  }

  return createWithdrawal(request, env);
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
    if (url.pathname === "/api/production") {
  return handleProduction(request, env);
}
    if (url.pathname === "/api/stock") return handleStockApi(request, env);
if (url.pathname === "/api/movements") return handleMovements(request, env);
if (url.pathname === "/api/withdrawals") return handleWithdrawalsApi(request, env);

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
