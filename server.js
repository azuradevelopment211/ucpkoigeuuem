require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const SteamStrategy = require("passport-steam").Strategy;
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const BASE_URL = (process.env.BASE_URL || "").replace(/\/$/, "");

if (!BASE_URL) {
  console.error("PUUDUB BASE_URL environment variable");
}

if (!process.env.SUPABASE_URL) {
  console.error("PUUDUB SUPABASE_URL environment variable");
}

if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error("PUUDUB SUPABASE_SERVICE_ROLE_KEY environment variable");
}

if (!process.env.STEAM_API_KEY) {
  console.error("PUUDUB STEAM_API_KEY environment variable");
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("trust proxy", 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: true,
      sameSite: "lax",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

function steamId64ToHex(steamId64) {
  const steamId = BigInt(steamId64);
  const base = BigInt("76561197960265728");
  return "steam:" + (steamId - base).toString(16);
}

passport.use(
  new SteamStrategy(
    {
      returnURL: `${BASE_URL}/auth/steam/return`,
      realm: `${BASE_URL}/`,
      apiKey: process.env.STEAM_API_KEY,
      stateless: true,
    },
    async (identifier, profile, done) => {
      try {
        const steamId = profile.id;
        const steamHex = steamId64ToHex(steamId);
        const username = profile.displayName || "Steam User";
        const avatar =
          profile.photos?.[2]?.value ||
          profile.photos?.[1]?.value ||
          profile.photos?.[0]?.value ||
          null;

        const role = steamId === process.env.ADMIN_STEAM_ID ? "admin" : "user";

        const { data: existingUser, error: findError } = await supabase
          .from("users")
          .select("*")
          .eq("steam_id", steamId)
          .maybeSingle();

        if (findError) {
          console.error("SUPABASE FIND USER ERROR:", findError);
          return done(findError);
        }

        if (existingUser) {
          const { data: updatedUser, error: updateError } = await supabase
            .from("users")
            .update({
              username,
              avatar,
              steam_hex: steamHex,
              role,
            })
            .eq("id", existingUser.id)
            .select()
            .single();

          if (updateError) {
            console.error("SUPABASE UPDATE USER ERROR:", updateError);
            return done(updateError);
          }

          return done(null, updatedUser);
        }

        const { data: newUser, error: insertError } = await supabase
          .from("users")
          .insert({
            steam_id: steamId,
            steam_hex: steamHex,
            username,
            avatar,
            role,
          })
          .select()
          .single();

        if (insertError) {
          console.error("SUPABASE INSERT USER ERROR:", insertError);
          return done(insertError);
        }

        return done(null, newUser);
      } catch (err) {
        console.error("STEAM STRATEGY ERROR:", err);
        return done(err);
      }
    }
  )
);

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.redirect("/");
  }

  return next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).send("Ainult admin saab siia.");
  }

  return next();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function page(title, content) {
  return `
    <!doctype html>
    <html lang="et">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>${escapeHtml(title)}</title>
        <style>
          * { box-sizing: border-box; }
          body {
            font-family: Arial, sans-serif;
            background: #111827;
            color: #f9fafb;
            margin: 0;
            padding: 40px 18px;
          }
          .wrap {
            max-width: 900px;
            margin: 0 auto;
          }
          .card {
            background: #1f2937;
            padding: 22px;
            border-radius: 14px;
            margin: 16px 0;
            border: 1px solid #374151;
          }
          a, button {
            display: inline-block;
            background: #2563eb;
            color: white;
            padding: 10px 14px;
            border-radius: 8px;
            text-decoration: none;
            border: 0;
            cursor: pointer;
            font-size: 15px;
          }
          button:hover, a:hover { opacity: .9; }
          input, textarea {
            width: 100%;
            max-width: 620px;
            padding: 11px;
            margin: 7px 0;
            border-radius: 8px;
            border: 1px solid #374151;
            background: #111827;
            color: white;
          }
          textarea { min-height: 90px; }
          .muted { color: #9ca3af; }
          .danger { color: #fca5a5; }
          .ok { color: #86efac; }
          img.avatar {
            width: 84px;
            height: 84px;
            border-radius: 12px;
          }
          code {
            background: #0f172a;
            padding: 3px 6px;
            border-radius: 6px;
          }
        </style>
      </head>
      <body>
        <div class="wrap">
          ${content}
        </div>
      </body>
    </html>
  `;
}

app.get("/", (req, res) => {
  res.send(
    page(
      "FiveM UCP",
      `
      <div class="card">
        <h1>FiveM UCP</h1>
        ${
          req.user
            ? `<p>Oled sisse loginud: <b>${escapeHtml(req.user.username)}</b></p>
               <a href="/dashboard">Dashboard</a>`
            : `<p class="muted">Logi Steamiga sisse, et whitelist avaldust teha.</p>
               <a href="/auth/steam">Login with Steam</a>`
        }
      </div>
      `
    )
  );
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    baseUrl: BASE_URL,
    hasSupabaseUrl: Boolean(process.env.SUPABASE_URL),
    hasSupabaseServiceRoleKey: Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY),
    hasSteamApiKey: Boolean(process.env.STEAM_API_KEY),
  });
});

app.get("/auth/steam", passport.authenticate("steam"));

app.get("/auth/steam/return", (req, res, next) => {
  passport.authenticate("steam", (err, user) => {
    if (err) {
      console.error("STEAM AUTH ERROR:", err);
      return res.status(500).send("Steam login error. Vaata Render Logs.");
    }

    if (!user) {
      return res.redirect("/");
    }

    req.logIn(user, (loginErr) => {
      if (loginErr) {
        console.error("LOGIN SESSION ERROR:", loginErr);
        return res.status(500).send("Session login error. Vaata Render Logs.");
      }

      return res.redirect("/dashboard");
    });
  })(req, res, next);
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("steam_id", req.user.steam_id)
    .single();

  if (error || !user) {
    console.error("DASHBOARD USER ERROR:", error);
    return res.status(500).send("Kasutajat ei leitud. Vaata Render Logs.");
  }

  res.send(
    page(
      "Dashboard",
      `
      <div class="card">
        <h1>Dashboard</h1>
        ${user.avatar ? `<img class="avatar" src="${escapeHtml(user.avatar)}" />` : ""}
        <p>Kasutaja: <b>${escapeHtml(user.username)}</b></p>
        <p>SteamID64: <code>${escapeHtml(user.steam_id)}</code></p>
        <p>Steam HEX: <code>${escapeHtml(user.steam_hex)}</code></p>
        <p>Whitelist: ${
          user.is_whitelisted
            ? `<b class="ok">Jah</b>`
            : `<b class="danger">Ei</b>`
        }</p>
        <p>Roll: <b>${escapeHtml(user.role)}</b></p>
        <a href="/logout">Logi välja</a>
      </div>

      <div class="card">
        <h2>Whitelist avaldus</h2>
        <form method="POST" action="/whitelist/apply">
          <input name="age" placeholder="Vanus" required />
          <input name="character_name" placeholder="Karakteri nimi" required />
          <textarea name="experience" placeholder="RP kogemus" required></textarea>
          <textarea name="why" placeholder="Miks tahad serverisse?" required></textarea>
          <button type="submit">Saada avaldus</button>
        </form>
      </div>

      <div class="card">
        <h2>UCP pood</h2>
        <a href="/shop">Vaata poodi</a>
      </div>

      ${
        user.role === "admin"
          ? `<div class="card">
              <h2>Admin</h2>
              <a href="/admin/whitelist">Whitelist avaldused</a>
            </div>`
          : ""
      }
      `
    )
  );
});

app.post("/whitelist/apply", requireAuth, async (req, res) => {
  const { age, character_name, experience, why } = req.body;

  const { data: user, error: userError } = await supabase
    .from("users")
    .select("*")
    .eq("steam_id", req.user.steam_id)
    .single();

  if (userError || !user) {
    console.error("WHITELIST USER ERROR:", userError);
    return res.status(500).send("Kasutajat ei leitud.");
  }

  const { error } = await supabase.from("whitelist_applications").insert({
    user_id: user.id,
    age: Number(age),
    character_name,
    experience,
    answers: { why },
    status: "pending",
  });

  if (error) {
    console.error("WHITELIST INSERT ERROR:", error);
    return res.status(500).send("Viga avalduse saatmisel.");
  }

  res.send(
    page(
      "Avaldus saadetud",
      `
      <div class="card">
        <h1>Avaldus saadetud!</h1>
        <p class="muted">Admin vaatab selle üle.</p>
        <a href="/dashboard">Tagasi</a>
      </div>
      `
    )
  );
});

app.get("/admin/whitelist", requireAuth, requireAdmin, async (req, res) => {
  const { data: applications, error } = await supabase
    .from("whitelist_applications")
    .select("*, users(username, steam_id, steam_hex)")
    .order("created_at", { ascending: false });

  if (error) {
    console.error("ADMIN WHITELIST LOAD ERROR:", error);
    return res.status(500).send("Viga avalduste laadimisel.");
  }

  const html = (applications || [])
    .map(
      (app) => `
      <div class="card">
        <p><b>Kasutaja:</b> ${escapeHtml(app.users?.username)}</p>
        <p><b>SteamID64:</b> <code>${escapeHtml(app.users?.steam_id)}</code></p>
        <p><b>Steam HEX:</b> <code>${escapeHtml(app.users?.steam_hex)}</code></p>
        <p><b>Karakter:</b> ${escapeHtml(app.character_name)}</p>
        <p><b>Vanus:</b> ${escapeHtml(app.age)}</p>
        <p><b>Kogemus:</b> ${escapeHtml(app.experience)}</p>
        <p><b>Miks:</b> ${escapeHtml(app.answers?.why)}</p>
        <p><b>Status:</b> ${escapeHtml(app.status)}</p>

        <form method="POST" action="/admin/whitelist/${escapeHtml(app.id)}/approve" style="display:inline;">
          <button type="submit">Kinnita whitelist</button>
        </form>

        <form method="POST" action="/admin/whitelist/${escapeHtml(app.id)}/reject" style="display:inline;">
          <button type="submit" style="background:#dc2626;">Lükka tagasi</button>
        </form>
      </div>
    `
    )
    .join("");

  res.send(
    page(
      "Admin whitelist",
      `
      <h1>Whitelist avaldused</h1>
      ${html || `<div class="card"><p class="muted">Avaldusi ei ole.</p></div>`}
      <br/>
      <a href="/dashboard">Tagasi</a>
      `
    )
  );
});

app.post("/admin/whitelist/:id/approve", requireAuth, requireAdmin, async (req, res) => {
  const applicationId = req.params.id;

  const { data: application, error } = await supabase
    .from("whitelist_applications")
    .select("*")
    .eq("id", applicationId)
    .single();

  if (error || !application) {
    console.error("APPROVE FIND ERROR:", error);
    return res.status(404).send("Avaldust ei leitud.");
  }

  const { error: updateUserError } = await supabase
    .from("users")
    .update({ is_whitelisted: true })
    .eq("id", application.user_id);

  if (updateUserError) {
    console.error("APPROVE USER UPDATE ERROR:", updateUserError);
    return res.status(500).send("Kasutaja whitelist muutmine ebaõnnestus.");
  }

  const { error: updateAppError } = await supabase
    .from("whitelist_applications")
    .update({
      status: "approved",
      reviewed_at: new Date().toISOString(),
    })
    .eq("id", applicationId);

  if (updateAppError) {
    console.error("APPROVE APP UPDATE ERROR:", updateAppError);
    return res.status(500).send("Avalduse muutmine ebaõnnestus.");
  }

  res.redirect("/admin/whitelist");
});

app.post("/admin/whitelist/:id/reject", requireAuth, requireAdmin, async (req, res) => {
  const applicationId = req.params.id;

  const { error } = await supabase
    .from("whitelist_applications")
    .update({
      status: "rejected",
      reviewed_at: new Date().toISOString(),
    })
    .eq("id", applicationId);

  if (error) {
    console.error("REJECT APP ERROR:", error);
    return res.status(500).send("Avalduse tagasilükkamine ebaõnnestus.");
  }

  res.redirect("/admin/whitelist");
});

app.get("/shop", requireAuth, async (req, res) => {
  const { data: products, error } = await supabase
    .from("shop_products")
    .select("*")
    .eq("active", true)
    .order("created_at", { ascending: false });

  if (error) {
    console.error("SHOP LOAD ERROR:", error);
    return res.status(500).send("Poe laadimine ebaõnnestus.");
  }

  const html = (products || [])
    .map(
      (p) => `
      <div class="card">
        <h3>${escapeHtml(p.name)}</h3>
        <p>${escapeHtml(p.description)}</p>
        <p>Hind: <b>${escapeHtml(p.price)}</b></p>
        <form method="POST" action="/shop/purchase/${escapeHtml(p.id)}">
          <button type="submit">Osta testina</button>
        </form>
      </div>
    `
    )
    .join("");

  res.send(
    page(
      "UCP pood",
      `
      <h1>UCP Pood</h1>
      ${html || `<div class="card"><p class="muted">Tooteid ei ole.</p></div>`}
      <br/>
      <a href="/dashboard">Tagasi</a>
      `
    )
  );
});

app.post("/shop/purchase/:productId", requireAuth, async (req, res) => {
  const { data: user, error: userError } = await supabase
    .from("users")
    .select("*")
    .eq("steam_id", req.user.steam_id)
    .single();

  if (userError || !user) {
    console.error("PURCHASE USER ERROR:", userError);
    return res.status(500).send("Kasutajat ei leitud.");
  }

  const { error } = await supabase.from("orders").insert({
    user_id: user.id,
    product_id: req.params.productId,
    status: "paid_test",
    payment_provider: "test",
  });

  if (error) {
    console.error("PURCHASE INSERT ERROR:", error);
    return res.status(500).send("Ostu tegemisel tekkis viga.");
  }

  res.send(
    page(
      "Ost tehtud",
      `
      <div class="card">
        <h1>Ost lisatud testina!</h1>
        <a href="/shop">Tagasi poodi</a>
      </div>
      `
    )
  );
});

app.get("/api/fivem/check-whitelist", async (req, res) => {
  const secret = req.headers["x-ucp-secret"];

  if (secret !== process.env.FIVEM_API_SECRET) {
    return res.status(403).send("forbidden");
  }

  const steamHex = req.query.steam;

  if (!steamHex) {
    return res.status(400).send("missing steam");
  }

  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("steam_hex", steamHex)
    .maybeSingle();

  if (error) {
    console.error("FIVEM WHITELIST CHECK ERROR:", error);
    return res.status(500).send("error");
  }

  if (user && user.is_whitelisted) {
    return res.send("allowed");
  }

  return res.send("denied");
});

app.use((req, res) => {
  res.status(404).send(
    page(
      "404",
      `
      <div class="card">
        <h1>404</h1>
        <p>Lehte ei leitud: <code>${escapeHtml(req.path)}</code></p>
        <a href="/">Tagasi avalehele</a>
      </div>
      `
    )
  );
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`UCP running on port ${process.env.PORT || 3000}`);
});
