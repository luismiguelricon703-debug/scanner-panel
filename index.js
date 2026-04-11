const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ======================
// CONFIG
// ======================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

app.use(
  session({
    secret: "secret123",
    resave: false,
    saveUninitialized: false,
  })
);

// ======================
// DB
// ======================
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    console.log("Error conectando DB:", err.message);
  } else {
    console.log("Base de datos conectada");
  }
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'cliente',
      plan TEXT DEFAULT 'free',
      scans_hoy INTEGER DEFAULT 0,
      ultimo_reset TEXT,
      expira TEXT,
      creado_en TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE,
      user_id INTEGER,
      estado TEXT DEFAULT 'pendiente',
      resultado TEXT DEFAULT 'pendiente',
      detalle TEXT,
      fecha_creacion TEXT,
      fecha_resultado TEXT
    )
  `);

  console.log("Tablas listas");
});

// ======================
// FUNCIONES
// ======================
function generarCode() {
  return "SCAN-" + Math.random().toString(36).substring(2, 8).toUpperCase();
}

function hoyTexto() {
  return new Date().toISOString().split("T")[0];
}

function sumarDias(dias) {
  const fecha = new Date();
  fecha.setDate(fecha.getDate() + dias);
  return fecha.toISOString();
}

function resetScansSiHaceFalta(user, callback) {
  const hoy = hoyTexto();

  if (user.ultimo_reset !== hoy) {
    db.run(
      `UPDATE users SET scans_hoy = 0, ultimo_reset = ? WHERE id = ?`,
      [hoy, user.id],
      (err) => {
        if (err) return callback(err);
        user.scans_hoy = 0;
        user.ultimo_reset = hoy;
        callback(null, user);
      }
    );
  } else {
    callback(null, user);
  }
}

function auth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  next();
}

function adminOnly(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }

  db.get(
    `SELECT * FROM users WHERE id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err || !user) {
        return res.redirect("/login");
      }

      if (user.role !== "owner") {
        return res.send(
          renderPage(
            "Sin acceso",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <h1>Acceso denegado</h1>
                <p class="muted">Solo el dueño puede entrar aquí.</p>
                <div class="actions">
                  <a class="btn" href="/dashboard">Volver</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }

      next();
    }
  );
}

function formatFecha(fecha) {
  if (!fecha) return "Sin fecha";
  try {
    return new Date(fecha).toLocaleString("es-ES");
  } catch {
    return fecha;
  }
}

function badgeClass(resultado) {
  if (resultado === "limpio") return "badge-limpio";
  if (resultado === "sospechoso") return "badge-sospechoso";
  if (resultado === "detectado") return "badge-detectado";
  if (resultado === "en_proceso") return "badge-proceso";
  return "badge-pendiente";
}

function estadoClass(estado) {
  if (estado === "completado") return "badge-limpio";
  if (estado === "en_proceso") return "badge-proceso";
  if (estado === "revision") return "badge-sospechoso";
  return "badge-pendiente";
}

function renderPage(title, content) {
  return `
  <!DOCTYPE html>
  <html lang="es">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <link rel="stylesheet" href="/styles.css">
  </head>
  <body>
    <div class="page-shell">
      ${content}
    </div>
  </body>
  </html>
  `;
}

// ======================
// RUTAS HTML EN RAIZ
// ======================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.get("/dashboard-page", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/admin-page", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// ======================
// REGISTRO
// ======================
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.send(
        renderPage(
          "Registro",
          `
          <div class="center-wrap">
            <div class="pro-card small-card">
              <h1>Faltan datos</h1>
              <p class="muted">Debes completar correo y contraseña.</p>
              <div class="actions">
                <a class="btn" href="/register">Volver</a>
              </div>
            </div>
          </div>
          `
        )
      );
    }

    const hash = await bcrypt.hash(password, 10);
    const fecha = new Date().toISOString();
    const hoy = hoyTexto();

    db.run(
      `INSERT INTO users (email, password, creado_en, ultimo_reset, role) VALUES (?, ?, ?, ?, ?)`,
      [email, hash, fecha, hoy, "cliente"],
      function (err) {
        if (err) {
          return res.send(
            renderPage(
              "Error",
              `
              <div class="center-wrap">
                <div class="pro-card small-card">
                  <h1>Error al registrar</h1>
                  <p class="muted">${err.message}</p>
                  <div class="actions">
                    <a class="btn" href="/register">Volver</a>
                  </div>
                </div>
              </div>
              `
            )
          );
        }

        res.send(
          renderPage(
            "Registro exitoso",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <h1>Usuario registrado correctamente</h1>
                <p class="muted">Ya puedes entrar a tu cuenta.</p>
                <div class="actions">
                  <a class="btn" href="/login">Ir al login</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }
    );
  } catch (error) {
    res.send(
      renderPage(
        "Error",
        `
        <div class="center-wrap">
          <div class="pro-card small-card">
            <h1>Error al registrar usuario</h1>
            <div class="actions">
              <a class="btn" href="/register">Volver</a>
            </div>
          </div>
        </div>
        `
      )
    );
  }
});

// ======================
// LOGIN
// ======================
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err) {
      return res.send(
        renderPage(
          "Error",
          `
          <div class="center-wrap">
            <div class="pro-card small-card">
              <h1>Error en base de datos</h1>
              <p class="muted">${err.message}</p>
              <div class="actions">
                <a class="btn" href="/login">Volver</a>
              </div>
            </div>
          </div>
          `
        )
      );
    }

    if (!user) {
      return res.send(
        renderPage(
          "Login",
          `
          <div class="center-wrap">
            <div class="pro-card small-card">
              <h1>Usuario no encontrado</h1>
              <div class="actions">
                <a class="btn" href="/login">Volver</a>
              </div>
            </div>
          </div>
          `
        )
      );
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.send(
        renderPage(
          "Login",
          `
          <div class="center-wrap">
            <div class="pro-card small-card">
              <h1>Contraseña incorrecta</h1>
              <div class="actions">
                <a class="btn" href="/login">Volver</a>
              </div>
            </div>
          </div>
          `
        )
      );
    }

    req.session.userId = user.id;
    res.redirect("/dashboard");
  });
});

// ======================
// LOGOUT
// ======================
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// ======================
// DASHBOARD
// ======================
app.get("/dashboard", auth, (req, res) => {
  db.get(
    `SELECT * FROM users WHERE id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err || !user) {
        return res.redirect("/login");
      }

      resetScansSiHaceFalta(user, (resetErr, userActualizado) => {
        if (resetErr) {
          return res.send(
            renderPage(
              "Error",
              `
              <div class="center-wrap">
                <div class="pro-card small-card">
                  <h1>Error reseteando scans</h1>
                  <div class="actions">
                    <a class="btn" href="/dashboard">Volver</a>
                  </div>
                </div>
              </div>
              `
            )
          );
        }

        db.all(
          `SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC`,
          [user.id],
          (err2, scans) => {
            if (err2) {
              return res.send(
                renderPage(
                  "Error",
                  `
                  <div class="center-wrap">
                    <div class="pro-card small-card">
                      <h1>Error cargando scans</h1>
                      <div class="actions">
                        <a class="btn" href="/dashboard">Volver</a>
                      </div>
                    </div>
                  </div>
                  `
                )
              );
            }

            const totalScans = scans.length;
            const pendientes = scans.filter((s) => s.estado === "pendiente").length;
            const completados = scans.filter((s) => s.estado === "completado").length;

            const filas = scans.length
              ? scans
                  .map(
                    (scan) => `
                  <tr>
                    <td>${scan.code}</td>
                    <td><span class="badge ${estadoClass(scan.estado)}">${scan.estado}</span></td>
                    <td><span class="badge ${badgeClass(scan.resultado)}">${scan.resultado}</span></td>
                    <td>${formatFecha(scan.fecha_creacion)}</td>
                  </tr>
                `
                  )
                  .join("")
              : `<tr><td colspan="4">No tienes scans todavía</td></tr>`;

            const botonAdmin =
              user.role === "owner"
                ? `<a class="btn btn-secondary" href="/admin">Panel admin</a>`
                : "";

            res.send(
              renderPage(
                "Dashboard",
                `
                <div class="dashboard-shell">
                  <aside class="sidebar">
                    <div class="sidebar-logo">SCANNER</div>
                    <div class="sidebar-user">
                      <div class="sidebar-label">Cuenta</div>
                      <div class="sidebar-email">${user.email}</div>
                    </div>

                    <nav class="sidebar-nav">
                      <a class="nav-item active" href="/dashboard">Dashboard</a>
                      ${user.role === "owner" ? `<a class="nav-item" href="/admin">Admin</a>` : ""}
                      <a class="nav-item danger" href="/logout">Cerrar sesión</a>
                    </nav>
                  </aside>

                  <main class="main-content">
                    <div class="topbar">
                      <div>
                        <h1 class="page-title">Dashboard</h1>
                        <p class="page-subtitle">Panel privado de gestión de escaneos</p>
                      </div>
                      <div class="actions">
                        <form method="POST" action="/create-scan">
                          <button class="btn" type="submit">Crear Scan</button>
                        </form>
                        ${botonAdmin}
                      </div>
                    </div>

                    <section class="stats-grid">
                      <div class="stat-card">
                        <div class="stat-label">Plan</div>
                        <div class="stat-value">${userActualizado.plan}</div>
                      </div>

                      <div class="stat-card">
                        <div class="stat-label">Scans hoy</div>
                        <div class="stat-value">${userActualizado.scans_hoy}/4</div>
                      </div>

                      <div class="stat-card">
                        <div class="stat-label">Total scans</div>
                        <div class="stat-value">${totalScans}</div>
                      </div>

                      <div class="stat-card">
                        <div class="stat-label">Pendientes</div>
                        <div class="stat-value">${pendientes}</div>
                      </div>

                      <div class="stat-card">
                        <div class="stat-label">Completados</div>
                        <div class="stat-value">${completados}</div>
                      </div>

                      <div class="stat-card">
                        <div class="stat-label">Expira</div>
                        <div class="stat-value small-text">${
                          userActualizado.expira ? formatFecha(userActualizado.expira) : "Sin fecha"
                        }</div>
                      </div>
                    </section>

                    <section class="panel-card">
                      <div class="panel-header">
                        <h2>Mis scans</h2>
                        <p class="muted">Solo los usuarios con acceso pueden generar PIN.</p>
                      </div>

                      <div class="table-wrap">
                        <table>
                          <tr>
                            <th>Código</th>
                            <th>Estado</th>
                            <th>Resultado</th>
                            <th>Fecha</th>
                          </tr>
                          ${filas}
                        </table>
                      </div>
                    </section>
                  </main>
                </div>
                `
              )
            );
          }
        );
      });
    }
  );
});

// ======================
// CREAR SCAN
// ======================
app.post("/create-scan", auth, (req, res) => {
  db.get(
    `SELECT * FROM users WHERE id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err || !user) {
        return res.redirect("/login");
      }

      resetScansSiHaceFalta(user, (resetErr, userActualizado) => {
        if (resetErr) {
          return res.send(
            renderPage(
              "Error",
              `
              <div class="center-wrap">
                <div class="pro-card small-card">
                  <h1>Error al validar scans</h1>
                  <div class="actions">
                    <a class="btn" href="/dashboard">Volver</a>
                  </div>
                </div>
              </div>
              `
            )
          );
        }

        if (userActualizado.plan === "free") {
          return res.send(
            renderPage(
              "Plan requerido",
              `
              <div class="center-wrap">
                <div class="pro-card small-card">
                  <h1>No tienes plan activo</h1>
                  <p class="muted">Pide activación al dueño o administrador.</p>
                  <div class="actions">
                    <a class="btn" href="/dashboard">Volver</a>
                  </div>
                </div>
              </div>
              `
            )
          );
        }

        if (
          userActualizado.plan !== "lifetime" &&
          userActualizado.expira &&
          new Date(userActualizado.expira) < new Date()
        ) {
          return res.send(
            renderPage(
              "Plan expirado",
              `
              <div class="center-wrap">
                <div class="pro-card small-card">
                  <h1>Tu plan expiró</h1>
                  <div class="actions">
                    <a class="btn" href="/dashboard">Volver</a>
                  </div>
                </div>
              </div>
              `
            )
          );
        }

        if (userActualizado.scans_hoy >= 4) {
          return res.send(
            renderPage(
              "Límite alcanzado",
              `
              <div class="center-wrap">
                <div class="pro-card small-card">
                  <h1>Ya usaste tus 4 scans de hoy</h1>
                  <div class="actions">
                    <a class="btn" href="/dashboard">Volver</a>
                  </div>
                </div>
              </div>
              `
            )
          );
        }

        const code = generarCode();
        const fecha = new Date().toISOString();

        db.run(
          `INSERT INTO scans (code, user_id, fecha_creacion, estado, resultado) VALUES (?, ?, ?, ?, ?)`,
          [code, user.id, fecha, "pendiente", "pendiente"],
          function (err2) {
            if (err2) {
              return res.send(
                renderPage(
                  "Error",
                  `
                  <div class="center-wrap">
                    <div class="pro-card small-card">
                      <h1>Error creando scan</h1>
                      <p class="muted">${err2.message}</p>
                      <div class="actions">
                        <a class="btn" href="/dashboard">Volver</a>
                      </div>
                    </div>
                  </div>
                  `
                )
              );
            }

            db.run(
              `UPDATE users SET scans_hoy = scans_hoy + 1 WHERE id = ?`,
              [user.id],
              (err3) => {
                if (err3) {
                  return res.send(
                    renderPage(
                      "Error",
                      `
                      <div class="center-wrap">
                        <div class="pro-card small-card">
                          <h1>Error actualizando scans</h1>
                          <div class="actions">
                            <a class="btn" href="/dashboard">Volver</a>
                          </div>
                        </div>
                      </div>
                      `
                    )
                  );
                }

                res.send(
                  renderPage(
                    "Scan creado",
                    `
                    <div class="center-wrap">
                      <div class="pro-card scan-process-card">
                        <div class="hero-badge">Nuevo PIN generado</div>
                        <h1>Scan creado correctamente</h1>

                        <div class="pin-box">${code}</div>

                        <div class="process-grid">
                          <div class="process-item">
                            <span class="label">Estado</span>
                            <span class="badge badge-pendiente">pendiente</span>
                          </div>
                          <div class="process-item">
                            <span class="label">Resultado</span>
                            <span class="badge badge-pendiente">pendiente</span>
                          </div>
                        </div>

                        <div class="instructions-box">
                          <h3>Instrucciones</h3>
                          <ol>
                            <li>Pásale este PIN a la persona que va a ejecutar el proceso.</li>
                            <li>Esa persona abre la página externa del scan.</li>
                            <li>Después descarga el scanner, lo ejecuta y presiona Start.</li>
                            <li>El resultado solo lo verán los usuarios con acceso al panel y el dueño.</li>
                          </ol>
                        </div>

                        <div class="actions center-actions">
                          <a class="btn" href="/dashboard">Volver al dashboard</a>
                          <a class="btn btn-secondary" href="/start/${code}">Ir a página externa</a>
                          <a class="btn btn-secondary" href="/scan/${code}">Ver detalle privado</a>
                        </div>
                      </div>
                    </div>
                    `
                  )
                );
              }
            );
          }
        );
      });
    }
  );
});

// ======================
// DETALLE PRIVADO
// ======================
app.get("/scan/:code", auth, (req, res) => {
  const { code } = req.params;

  db.get(
    `SELECT scans.*, users.id as owner_id FROM scans
     LEFT JOIN users ON scans.user_id = users.id
     WHERE scans.code = ?`,
    [code],
    (err, scan) => {
      if (err || !scan) {
        return res.send(
          renderPage(
            "No encontrado",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <h1>Scan no encontrado</h1>
                <div class="actions">
                  <a class="btn" href="/dashboard">Volver</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }

      db.get(
        `SELECT * FROM users WHERE id = ?`,
        [req.session.userId],
        (err2, currentUser) => {
          if (err2 || !currentUser) {
            return res.redirect("/login");
          }

          if (currentUser.role !== "owner" && scan.user_id !== currentUser.id) {
            return res.send(
              renderPage(
                "Sin acceso",
                `
                <div class="center-wrap">
                  <div class="pro-card small-card">
                    <h1>No tienes acceso a este scan</h1>
                    <div class="actions">
                      <a class="btn" href="/dashboard">Volver</a>
                    </div>
                  </div>
                </div>
                `
              )
            );
          }

          res.send(
            renderPage(
              "Detalle del Scan",
              `
              <div class="center-wrap">
                <div class="pro-card scan-process-card">
                  <div class="hero-badge">Detalle del proceso</div>
                  <h1>Scan ${scan.code}</h1>

                  <div class="process-grid">
                    <div class="process-item">
                      <span class="label">Estado</span>
                      <span class="badge ${estadoClass(scan.estado)}">${scan.estado}</span>
                    </div>
                    <div class="process-item">
                      <span class="label">Resultado</span>
                      <span class="badge ${badgeClass(scan.resultado)}">${scan.resultado}</span>
                    </div>
                    <div class="process-item">
                      <span class="label">Detalle</span>
                      <span class="value-text">${scan.detalle || "Sin detalle"}</span>
                    </div>
                    <div class="process-item">
                      <span class="label">Fecha creación</span>
                      <span class="value-text">${formatFecha(scan.fecha_creacion)}</span>
                    </div>
                    <div class="process-item">
                      <span class="label">Fecha resultado</span>
                      <span class="value-text">${
                        scan.fecha_resultado ? formatFecha(scan.fecha_resultado) : "Pendiente"
                      }</span>
                    </div>
                  </div>

                  <div class="actions center-actions">
                    <a class="btn" href="/dashboard">Volver</a>
                  </div>
                </div>
              </div>
              `
            )
          );
        }
      );
    }
  );
});

// ======================
// PAGINA EXTERNA DEL SCAN
// ======================
app.get("/start/:code", (req, res) => {
  const { code } = req.params;

  db.get(
    `SELECT * FROM scans WHERE code = ?`,
    [code],
    (err, scan) => {
      if (err || !scan) {
        return res.send(
          renderPage(
            "PIN no encontrado",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <div class="hero-badge">Escaneo externo</div>
                <h1>PIN no encontrado</h1>
                <p class="muted">El código ingresado no existe o ya no está disponible.</p>
                <div class="actions center-actions">
                  <a class="btn" href="/">Volver</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }

      let titulo = "Iniciar verificación";
      let subtitulo = "Descarga el scanner, ejecútalo y presiona Start.";
      let badge = `<span class="status-pill status-pending">Pendiente</span>`;
      let botonHtml = `
        <form method="POST" action="/start-scan/${scan.code}">
          <button class="btn start-btn" type="submit">START SCAN</button>
        </form>
      `;
      let progresoHtml = "";
      let logsHtml = `
        <div class="scan-logs">
          <div class="log-line neutral">[INFO] Código listo para iniciar.</div>
          <div class="log-line neutral">[INFO] Esperando acción del usuario.</div>
        </div>
      `;
      let scriptExtra = "";

      if (scan.estado === "en_proceso") {
        titulo = "Análisis en ejecución";
        subtitulo = "No cierres esta ventana mientras el sistema completa el proceso.";
        badge = `<span class="status-pill status-processing">En proceso</span>`;
        botonHtml = `<button class="btn btn-secondary" disabled>SCAN EN PROCESO</button>`;

        progresoHtml = `
          <div class="scan-progress-card">
            <div class="progress-header">
              <span>Progreso del análisis</span>
              <span id="progress-percent">65%</span>
            </div>
            <div class="progress-bar-pro">
              <div class="progress-fill-pro progress-animate-pro"></div>
            </div>
            <div class="progress-message" id="progressText">Escaneando sistema...</div>
          </div>
        `;

        logsHtml = `
          <div class="scan-logs" id="logBox">
            <div class="log-line success">[OK] Inicializando entorno...</div>
            <div class="log-line success">[OK] Verificando archivos temporales...</div>
            <div class="log-line success">[OK] Analizando procesos activos...</div>
          </div>
        `;

        scriptExtra = `
          <script>
            const mensajes = [
              "Escaneando sistema...",
              "Revisando procesos activos...",
              "Verificando integridad del entorno...",
              "Analizando rastros del sistema...",
              "Procesando información..."
            ];

            const porcentajes = ["65%", "71%", "78%", "84%", "91%"];
            let i = 0;

            const text = document.getElementById("progressText");
            const percent = document.getElementById("progress-percent");

            if (text && percent) {
              setInterval(() => {
                i = (i + 1) % mensajes.length;
                text.textContent = mensajes[i];
                percent.textContent = porcentajes[i];
              }, 1800);
            }

            const logBox = document.getElementById("logBox");
            const logs = [
              "[OK] Revisando servicios activos...",
              "[OK] Analizando actividad reciente...",
              "[OK] Verificando módulos cargados...",
              "[OK] Comprobando consistencia del entorno...",
              "[OK] Proceso en ejecución..."
            ];

            let logIndex = 0;
            if (logBox) {
              setInterval(() => {
                if (logIndex < logs.length) {
                  const div = document.createElement("div");
                  div.className = "log-line success";
                  div.textContent = logs[logIndex];
                  logBox.appendChild(div);
                  logIndex++;
                }
              }, 1600);
            }

            setTimeout(() => {
              window.location.reload();
            }, 9000);
          </script>
        `;
      }

      if (scan.estado === "revision") {
        titulo = "Proceso completado";
        subtitulo = "El análisis terminó y ahora está esperando validación del staff.";
        badge = `<span class="status-pill status-review">En revisión</span>`;
        botonHtml = `<button class="btn btn-secondary" disabled>EN REVISIÓN</button>`;

        progresoHtml = `
          <div class="scan-progress-card">
            <div class="progress-header">
              <span>Estado del análisis</span>
              <span>100%</span>
            </div>
            <div class="progress-bar-pro">
              <div class="progress-fill-pro progress-review-pro"></div>
            </div>
            <div class="progress-message">Proceso completado. Esperando validación del equipo.</div>
          </div>
        `;

        logsHtml = `
          <div class="scan-logs">
            <div class="log-line success">[OK] Proceso finalizado</div>
            <div class="log-line success">[OK] Datos enviados a revisión</div>
            <div class="log-line warning">[WAIT] Esperando validación del staff...</div>
          </div>
        `;
      }

      if (scan.estado === "completado") {
        titulo = "Verificación finalizada";
        subtitulo = "El proceso fue completado correctamente.";
        badge = `<span class="status-pill status-complete">Finalizado</span>`;
        botonHtml = `<button class="btn btn-secondary" disabled>SCAN FINALIZADO</button>`;

        progressoHtml = `
          <div class="scan-progress-card">
            <div class="progress-header">
              <span>Estado del análisis</span>
              <span>100%</span>
            </div>
            <div class="progress-bar-pro">
              <div class="progress-fill-pro progress-complete-pro"></div>
            </div>
            <div class="progress-message">Proceso finalizado correctamente.</div>
          </div>
        `;

        progresoHtml = `
          <div class="scan-progress-card">
            <div class="progress-header">
              <span>Estado del análisis</span>
              <span>100%</span>
            </div>
            <div class="progress-bar-pro">
              <div class="progress-fill-pro progress-complete-pro"></div>
            </div>
            <div class="progress-message">Proceso finalizado correctamente.</div>
          </div>
        `;

        logsHtml = `
          <div class="scan-logs">
            <div class="log-line success">[OK] Verificación completada</div>
            <div class="log-line success">[OK] Resultado enviado al panel privado</div>
          </div>
        `;
      }

      res.send(
        renderPage(
          "Start Scan",
          `
          <div class="center-wrap">
            <div class="pro-card scan-process-card external-scan-card">
              <div class="hero-badge">Escaneo externo</div>

              <div class="external-header">
                <div>
                  <h1>${titulo}</h1>
                  <p class="muted">${subtitulo}</p>
                </div>
                <div class="external-status">
                  ${badge}
                </div>
              </div>

              <div class="pin-box">${scan.code}</div>

              <div class="scan-info-grid">
                <div class="scan-info-card">
                  <span class="label">Código del scan</span>
                  <span class="value-text">${scan.code}</span>
                </div>
                <div class="scan-info-card">
                  <span class="label">Estado actual</span>
                  <span class="value-text">${scan.estado}</span>
                </div>
              </div>

              ${progresoHtml}

              <div class="instructions-box scan-instructions-pro">
                <h3>Pasos a seguir</h3>
                <ol>
                  <li>Descarga el scanner desde el enlace enviado por la persona responsable.</li>
                  <li>Ejecuta el archivo en tu equipo.</li>
                  <li>Presiona <strong>START SCAN</strong> para comenzar.</li>
                  <li>No cierres esta ventana hasta que el proceso termine.</li>
                  <li>Los resultados serán visibles solo para usuarios autorizados.</li>
                </ol>
              </div>

              <div class="logs-wrapper">
                <div class="logs-title">Registro del proceso</div>
                ${logsHtml}
              </div>

              <div class="actions center-actions">
                ${botonHtml}
              </div>
            </div>
          </div>
          ${scriptExtra}
          `
        )
      );
    }
  );
});

// ======================
// START SCAN CAMBIA A EN_PROCESO
// ======================
app.post("/start-scan/:code", (req, res) => {
  const { code } = req.params;

  db.run(
    `UPDATE scans SET estado = ? WHERE code = ?`,
    ["en_proceso", code],
    function (err) {
      if (err) {
        return res.send(
          renderPage(
            "Error",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <h1>Error al iniciar el scan</h1>
                <p class="muted">${err.message}</p>
                <div class="actions">
                  <a class="btn" href="/">Volver</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }

      if (this.changes === 0) {
        return res.send(
          renderPage(
            "No encontrado",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <h1>Scan no encontrado</h1>
                <div class="actions">
                  <a class="btn" href="/">Volver</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }

      setTimeout(() => {
        db.run(
          `UPDATE scans SET estado = ? WHERE code = ? AND estado = ?`,
          ["revision", code, "en_proceso"]
        );
      }, 8000);

      res.redirect(`/start/${code}`);
    }
  );
});

// ======================
// ADMIN SOLO OWNER
// ======================
app.get("/admin", adminOnly, (req, res) => {
  db.all(`SELECT * FROM users ORDER BY id DESC`, [], (err, users) => {
    if (err) {
      return res.send(
        renderPage(
          "Error",
          `
          <div class="center-wrap">
            <div class="pro-card small-card">
              <h1>Error cargando usuarios</h1>
              <div class="actions">
                <a class="btn" href="/dashboard">Volver</a>
              </div>
            </div>
          </div>
          `
        )
      );
    }

    db.all(`SELECT * FROM scans ORDER BY id DESC`, [], (err2, scans) => {
      if (err2) {
        return res.send(
          renderPage(
            "Error",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <h1>Error cargando scans</h1>
                <div class="actions">
                  <a class="btn" href="/dashboard">Volver</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }

      const filasUsers = users.length
        ? users
            .map(
              (user) => `
            <tr>
              <td>${user.id}</td>
              <td>${user.email}</td>
              <td>${user.role}</td>
              <td>${user.plan}</td>
              <td>${user.scans_hoy}/4</td>
              <td>${user.expira ? formatFecha(user.expira) : "Sin fecha"}</td>
              <td>
                <form method="POST" action="/admin/activar-plan" class="admin-inline-form">
                  <input type="hidden" name="user_id" value="${user.id}">
                  <select name="plan" required>
                    <option value="1dia">1 día</option>
                    <option value="mensual">mensual</option>
                    <option value="lifetime">lifetime</option>
                  </select>
                  <button class="btn small-btn" type="submit">Activar</button>
                </form>
              </td>
            </tr>
          `
            )
            .join("")
        : `<tr><td colspan="7">No hay usuarios</td></tr>`;

      const filasScans = scans.length
        ? scans
            .map(
              (scan) => `
            <tr>
              <td>${scan.id}</td>
              <td>${scan.code}</td>
              <td>${scan.user_id}</td>
              <td><span class="badge ${estadoClass(scan.estado)}">${scan.estado}</span></td>
              <td><span class="badge ${badgeClass(scan.resultado)}">${scan.resultado}</span></td>
              <td>${formatFecha(scan.fecha_creacion)}</td>
              <td>
                <form method="POST" action="/admin/actualizar-scan" class="admin-scan-form">
                  <input type="hidden" name="scan_id" value="${scan.id}">
                  <select name="estado" required>
                    <option value="pendiente">pendiente</option>
                    <option value="en_proceso">en_proceso</option>
                    <option value="revision">revision</option>
                    <option value="completado">completado</option>
                  </select>
                  <select name="resultado" required>
                    <option value="pendiente">pendiente</option>
                    <option value="limpio">limpio</option>
                    <option value="sospechoso">sospechoso</option>
                    <option value="detectado">detectado</option>
                  </select>
                  <input type="text" name="detalle" placeholder="Detalle">
                  <button class="btn small-btn" type="submit">Guardar</button>
                </form>
              </td>
            </tr>
          `
            )
            .join("")
        : `<tr><td colspan="7">No hay scans</td></tr>`;

      res.send(
        renderPage(
          "Admin",
          `
          <div class="dashboard-shell">
            <aside class="sidebar">
              <div class="sidebar-logo">SCANNER</div>
              <div class="sidebar-user">
                <div class="sidebar-label">Modo</div>
                <div class="sidebar-email">Owner Panel</div>
              </div>

              <nav class="sidebar-nav">
                <a class="nav-item" href="/dashboard">Dashboard</a>
                <a class="nav-item active" href="/admin">Admin</a>
                <a class="nav-item danger" href="/logout">Cerrar sesión</a>
              </nav>
            </aside>

            <main class="main-content">
              <div class="topbar">
                <div>
                  <h1 class="page-title">Panel Admin</h1>
                  <p class="page-subtitle">Gestión de clientes, planes y resultados</p>
                </div>
              </div>

              <section class="panel-card">
                <div class="panel-header">
                  <h2>Usuarios</h2>
                </div>

                <div class="table-wrap">
                  <table>
                    <tr>
                      <th>ID</th>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Plan</th>
                      <th>Scans hoy</th>
                      <th>Expira</th>
                      <th>Acción</th>
                    </tr>
                    ${filasUsers}
                  </table>
                </div>
              </section>

              <section class="panel-card">
                <div class="panel-header">
                  <h2>Scans</h2>
                </div>

                <div class="table-wrap">
                  <table>
                    <tr>
                      <th>ID</th>
                      <th>Código</th>
                      <th>User ID</th>
                      <th>Estado</th>
                      <th>Resultado</th>
                      <th>Fecha</th>
                      <th>Actualizar</th>
                    </tr>
                    ${filasScans}
                  </table>
                </div>
              </section>
            </main>
          </div>
          `
        )
      );
    });
  });
});

// ======================
// ACTIVAR PLAN
// ======================
app.post("/admin/activar-plan", adminOnly, (req, res) => {
  const { user_id, plan } = req.body;

  let expira = null;

  if (plan === "1dia") {
    expira = sumarDias(1);
  } else if (plan === "mensual") {
    expira = sumarDias(30);
  } else if (plan === "lifetime") {
    expira = null;
  } else {
    return res.send(
      renderPage(
        "Error",
        `
        <div class="center-wrap">
          <div class="pro-card small-card">
            <h1>Plan no válido</h1>
            <div class="actions">
              <a class="btn" href="/admin">Volver</a>
            </div>
          </div>
        </div>
        `
      )
    );
  }

  db.run(
    `UPDATE users SET plan = ?, expira = ?, scans_hoy = 0, ultimo_reset = ? WHERE id = ?`,
    [plan, expira, hoyTexto(), user_id],
    function (err) {
      if (err) {
        return res.send(
          renderPage(
            "Error",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <h1>Error activando plan</h1>
                <div class="actions">
                  <a class="btn" href="/admin">Volver</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }

      res.redirect("/admin");
    }
  );
});

// ======================
// ACTUALIZAR SCAN
// ======================
app.post("/admin/actualizar-scan", adminOnly, (req, res) => {
  const { scan_id, estado, resultado, detalle } = req.body;
  const fechaResultado = new Date().toISOString();

  db.run(
    `UPDATE scans SET estado = ?, resultado = ?, detalle = ?, fecha_resultado = ? WHERE id = ?`,
    [estado, resultado, detalle || "", fechaResultado, scan_id],
    function (err) {
      if (err) {
        return res.send(
          renderPage(
            "Error",
            `
            <div class="center-wrap">
              <div class="pro-card small-card">
                <h1>Error actualizando scan</h1>
                <div class="actions">
                  <a class="btn" href="/admin">Volver</a>
                </div>
              </div>
            </div>
            `
          )
        );
      }

      res.redirect("/admin");
    }
  );
});

// ======================
// HACER OWNER
// ======================
app.get("/hacer-owner", (req, res) => {
  if (!req.session.userId) {
    return res.send("❌ No estás logueado");
  }

  db.run(
    `UPDATE users SET role = 'owner' WHERE id = ?`,
    [req.session.userId],
    function (err) {
      if (err) {
        return res.send("❌ Error poniendo owner: " + err.message);
      }

      res.send(`
        <html lang="es">
        <head>
          <meta charset="UTF-8">
          <title>Owner activado</title>
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body>
          <div class="center-wrap">
            <div class="pro-card small-card">
              <div class="hero-badge">Acceso avanzado</div>
              <h1>🔥 Ahora eres OWNER 🔥</h1>
              <p class="muted">Ya puedes entrar al panel admin</p>

              <div class="actions" style="margin-top:20px;">
                <a class="btn" href="/admin-page">Ir al Admin</a>
                <a class="btn btn-secondary" href="/dashboard">Volver</a>
              </div>
            </div>
          </div>
        </body>
        </html>
      `);
    }
  );
});

// ======================
// SERVER
// ======================
app.listen(PORT, () => {
  console.log(`Servidor activo en http://localhost:${PORT}`);
});
