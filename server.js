require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const SteamStrategy = require("passport-steam").Strategy;
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

function steamId64ToHex(steamId64) {
  const steamId = BigInt(steamId64);
  const base = BigInt("76561197960265728");
  return "steam:" + (steamId - base).toString(16);
}
passport.use(
  new SteamStrategy(
    {
      returnURL: `${process.env.BASE_URL}/auth/steam/return`,
      realm: `${process.env.BASE_URL}/`,
      apiKey: process.env.STEAM_API_KEY,
      stateless: true,
    },
    async (identifier, profile, done) => {
      try {
        const steamId = profile.id;
        const steamHex = steamId64ToHex(steamId);
        const username = profile.displayName;
        const avatar = profile.photos?.[2]?.value || profile.photos?.[0]?.value || null;
        const role = steamId === process.env.ADMIN_STEAM_ID ? "admin" : "user";

        const { data: existingUser } = await supabase
          .from("users")
          .select("*")
          .eq("steam_id", steamId)
          .maybeSingle();

        if (existingUser) {
          const { data: updatedUser } = await supabase
            .from("users")
            .update({ username, avatar, steam_hex: steamHex, role })
            .eq("id", existingUser.id)
            .select()
            .single();

          return done(null, updatedUser || existingUser);
        }

        const { data: newUser, error } = await supabase
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

        if (error) return done(error);
        return done(null, newUser);
      } catch (err) {
        return done(err);
      }
    }
  )
);

function requireAuth(req, res, next) {
  if (!req.user) return res.redirect("/");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).send("Ainult admin saab siia.");
  }
  next();
}

function page(title, content) {
  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>${title}</title>
        <style>
          body { font-family: Arial, sans-serif; background:#111827; color:#f9fafb; margin:0; padding:40px; }
          a, button { background:#2563eb; color:white; padding:10px 14px; border-radius:8px; text-decoration:none; border:0; cursor:pointer; }
          input, textarea { width:100%; max-width:520px; padding:10px; margin:6px 0; border-radius:8px; border:1px solid #374151; }
          .card { background:#1f2937; padding:18px; border-radius:12px; margin:14px 0; max-width:760px; }
          .muted { color:#9ca3af; }
        </style>
      </head>
      <body>
        ${content}
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
            ? `<p>Oled sisse loginud: <b>${req.user.username}</b></p><a href="/dashboard">Dashboard</a>`
            : `<p class="muted">Logi Steamiga sisse, et whitelist avaldust teha.</p><a href="/auth/steam">Login with Steam</a>`
        }
      </div>
      `
    )
  );
});

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

app.get("/dashboard", requireAuth, async (req, res) => {
  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("steam_id", req.user.steam_id)
    .single();

  res.send(
    page(
      "Dashboard",
      `
      <div class="card">
        <h1>Dashboard</h1>
        <img src="${user.avatar || ""}" width="80" />
        <p>Kasutaja: <b>${user.username}</b></p>
        <p>SteamID64: ${user.steam_id}</p>
        <p>Steam HEX: ${user.steam_hex}</p>
        <p>Whitelist: <b>${user.is_whitelisted ? "Jah" : "Ei"}</b></p>
        <p>Roll: ${user.role}</p>
      </div>

      <div class="card">
        <h2>Whitelist avaldus</h2>
        <form method="POST" action="/whitelist/apply">
          <input name="age" placeholder="Vanus" required />
          <input name="character_name" placeholder="Karakteri nimi" required />
          <textarea name="experience" placeholder="RP kogemus" required></textarea>
          <textarea name="why" placeholder="Miks tahad serverisse?" required></textarea>
          <br/>
          <button type="submit">Saada avaldus</button>
        </form>
      </div>

      <div class="card">
        <h2>Pood</h2>
        <a href="/shop">Vaata poodi</a>
      </div>

      ${
        user.role === "admin"
          ? `<div class="card"><h2>Admin</h2><a href="/admin/whitelist">Whitelist avaldused</a></div>`
          : ""
      }
      `
    )
  );
});

app.post("/whitelist/apply", requireAuth, async (req, res) => {
  const { age, character_name, experience, why } = req.body;

  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("steam_id", req.user.steam_id)
    .single();

  const { error } = await supabase.from("whitelist_applications").insert({
    user_id: user.id,
    age: Number(age),
    character_name,
    experience,
    answers: { why },
    status: "pending",
  });

  if (error) return res.status(500).send("Viga avalduse saatmisel.");

  res.send(page("Avaldus saadetud", `<div class="card"><h1>Avaldus saadetud!</h1><a href="/dashboard">Tagasi</a></div>`));
});

app.get("/admin/whitelist", requireAuth, requireAdmin, async (req, res) => {
  const { data: applications, error } = await supabase
    .from("whitelist_applications")
    .select("*, users(username, steam_id, steam_hex)")
    .order("created_at", { ascending: false });

  if (error) return res.status(500).send("Viga avalduste laadimisel.");

  const html = applications
    .map(
      (app) => `
      <div class="card">
        <p><b>Kasutaja:</b> ${app.users?.username || ""}</p>
        <p><b>Steam:</b> ${app.users?.steam_id || ""}</p>
        <p><b>Steam HEX:</b> ${app.users?.steam_hex || ""}</p>
        <p><b>Karakter:</b> ${app.character_name}</p>
        <p><b>Vanus:</b> ${app.age}</p>
        <p><b>Kogemus:</b> ${app.experience}</p>
        <p><b>Miks:</b> ${app.answers?.why || ""}</p>
        <p><b>Status:</b> ${app.status}</p>
        <form method="POST" action="/admin/whitelist/${app.id}/approve">
          <button type="submit">Kinnita whitelist</button>
        </form>
      </div>
    `
    )
    .join("");

  res.send(page("Admin whitelist", `<h1>Whitelist avaldused</h1>${html}<br/><a href="/dashboard">Tagasi</a>`));
});

app.post("/admin/whitelist/:id/approve", requireAuth, requireAdmin, async (req, res) => {
  const applicationId = req.params.id;

  const { data: application, error } = await supabase
    .from("whitelist_applications")
    .select("*")
    .eq("id", applicationId)
    .single();

  if (error || !application) return res.status(404).send("Avaldust ei leitud.");

  await supabase.from("users").update({ is_whitelisted: true }).eq("id", application.user_id);

  await supabase
    .from("whitelist_applications")
    .update({
      status: "approved",
      reviewed_at: new Date().toISOString(),
    })
    .eq("id", applicationId);

  res.redirect("/admin/whitelist");
});

app.get("/shop", requireAuth, async (req, res) => {
  const { data: products } = await supabase.from("shop_products").select("*").eq("active", true);

  const html = (products || [])
    .map(
      (p) => `
      <div class="card">
        <h3>${p.name}</h3>
        <p>${p.description || ""}</p>
        <p>Hind: ${p.price}</p>
        <form method="POST" action="/shop/purchase/${p.id}">
          <button type="submit">Osta testina</button>
        </form>
      </div>
    `
    )
    .join("");

  res.send(page("UCP pood", `<h1>UCP Pood</h1>${html}<br/><a href="/dashboard">Tagasi</a>`));
});

app.post("/shop/purchase/:productId", requireAuth, async (req, res) => {
  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("steam_id", req.user.steam_id)
    .single();

  const { error } = await supabase.from("orders").insert({
    user_id: user.id,
    product_id: req.params.productId,
    status: "paid_test",
    payment_provider: "test",
  });

  if (error) return res.status(500).send("Ostu tegemisel tekkis viga.");

  res.send(page("Ost tehtud", `<div class="card"><h1>Ost lisatud testina!</h1><a href="/shop">Tagasi poodi</a></div>`));
});

app.get("/api/fivem/check-whitelist", async (req, res) => {
  const secret = req.headers["x-ucp-secret"];

  if (secret !== process.env.FIVEM_API_SECRET) return res.status(403).send("forbidden");

  const steamHex = req.query.steam;
  if (!steamHex) return res.status(400).send("missing steam");

  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("steam_hex", steamHex)
    .maybeSingle();

  if (user && user.is_whitelisted) return res.send("allowed");

  return res.send("denied");
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`UCP running on port ${process.env.PORT || 3000}`);
});
