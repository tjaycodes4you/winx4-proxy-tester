export default {
  async fetch(request) {
    const headers = {};
    for (const [k, v] of request.headers.entries()) headers[k] = v;
    return new Response(
      JSON.stringify({
        ip: headers["cf-connecting-ip"] || null,
        headers,
        ts: Date.now(),
      }),
      { headers: { "content-type": "application/json", "cache-control": "no-store" } },
    );
  },
};
