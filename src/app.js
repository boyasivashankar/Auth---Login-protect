require("dotenv").config();

const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const swaggerUi = require("swagger-ui-express");
const openApiSpec = require("../openapi.json");
const { requireAuth } = require("./middleware/auth");

// ---------------------------------------------------------------------------
// Environment validation
// ---------------------------------------------------------------------------
const { SUPABASE_URL, SUPABASE_KEY, PORT = 3000 } = process.env;

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());

if (!SUPABASE_URL || !SUPABASE_KEY) {
  // Don't process.exit() here: on a serverless platform this module runs
  // inside the request handler, and exiting kills the whole function
  // (FUNCTION_INVOCATION_FAILED) instead of returning a readable error.
  console.error(
    "❌  Missing SUPABASE_URL or SUPABASE_KEY in environment. " +
      "Set them in your deployment platform's environment variables " +
      "(see .env.example)."
  );

  app.use((_req, res) => {
    res.status(500).json({
      error:
        "Server misconfigured: missing SUPABASE_URL or SUPABASE_KEY environment variables.",
    });
  });
} else {
  // ---------------------------------------------------------------------------
  // Supabase client
  // ---------------------------------------------------------------------------
  const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  console.log("✅  Supabase client initialized →", SUPABASE_URL);

  // Swagger UI ----------------------------------------------------------------
  app.use("/docs", swaggerUi.serve, swaggerUi.setup(openApiSpec));

  // Shared auth middleware instance
  const auth = requireAuth(supabase);

  // ---------------------------------------------------------------------------
  // PUBLIC route
  // ---------------------------------------------------------------------------
  app.get("/public/info", (_req, res) => {
    res.status(200).json({ message: "Welcome stranger! This info is public." });
  });

  // ---------------------------------------------------------------------------
  // AUTH routes
  // ---------------------------------------------------------------------------

  // POST /auth/signup
  app.post("/auth/signup", async (req, res) => {
    const { email, password } = req.body ?? {};

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }

    const { data, error } = await supabase.auth.signUp({ email, password });

    if (error) {
      // Supabase returns status codes like 422 for weak passwords, 400 for
      // invalid email, etc.  Map known ranges; default to 400.
      const status = error.status && error.status >= 400 ? error.status : 400;
      return res.status(status).json({ error: error.message });
    }

    return res.status(201).json(data.user);
  });

  // POST /auth/login
  app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body ?? {};

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      return res.status(401).json({ error: "Invalid login credentials" });
    }

    return res.status(200).json({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
    });
  });

  // POST /auth/logout  — PROTECTED
  app.post("/auth/logout", auth, async (_req, res) => {
    // Sign out server-side. Errors are non-critical (token is already verified
    // by middleware) so we still return 204.
    await supabase.auth.signOut();
    return res.status(204).send();
  });

  // ---------------------------------------------------------------------------
  // PROTECTED route
  // ---------------------------------------------------------------------------

  // GET /protected/profile  — PROTECTED
  app.get("/protected/profile", auth, (req, res) => {
    const { id, email, created_at } = req.user;
    return res.status(200).json({ id, email, created_at });
  });
}

// ---------------------------------------------------------------------------
// Start server (only when run directly, not when imported by Vercel)
// ---------------------------------------------------------------------------
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`🚀  Server running on http://localhost:${PORT}`);
    console.log(`📄  API docs available at http://localhost:${PORT}/docs`);
  });
}

// Export the app for Vercel serverless deployment
module.exports = app;
