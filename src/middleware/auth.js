/**
 * Reusable Express middleware that verifies a Supabase access token.
 *
 * Reads the Authorization header, extracts the Bearer token, and calls
 * supabase.auth.getUser(token). On success it attaches the user to req.user
 * and calls next(). On any failure it responds with 401 JSON.
 *
 * @param {import("@supabase/supabase-js").SupabaseClient} supabase
 * @returns {import("express").RequestHandler}
 */
function requireAuth(supabase) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;

    // Header must exist, start with "Bearer ", and have a non-empty token.
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Access token required" });
    }

    const token = authHeader.slice(7); // strip "Bearer "

    if (!token) {
      return res.status(401).json({ error: "Access token required" });
    }

    try {
      const { data, error } = await supabase.auth.getUser(token);

      if (error || !data?.user) {
        return res.status(401).json({ error: "Invalid or expired token" });
      }

      // Attach the verified user to the request for downstream handlers.
      req.user = data.user;
      next();
    } catch {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}

module.exports = { requireAuth };
