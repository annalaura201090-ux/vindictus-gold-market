
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Pemeriksaan koneksi database
    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).all();

        return Response.json({
          status: "ok",
          database: "connected",
          tables: result.results
        });
      } catch (error) {
        return Response.json({
          status: "error",
          message: "Database belum terhubung"
        }, { status: 500 });
      }
    }

    // Tampilkan website dari folder public
    return env.ASSETS.fetch(request);
  }
};
