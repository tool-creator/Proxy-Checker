import fetch from "node-fetch";

export async function handler(event, context) {
  const headers = event.headers;
  const ip =
    headers["x-nf-client-connection-ip"] ||
    headers["x-forwarded-for"]?.split(",")[0] ||
    headers["client-ip"] ||
    headers["cf-connecting-ip"];

  try {
    const res = await fetch(`https://ipwho.is/${ip}`);
    const data = await res.json();

    let proxyScore = 0;
    const reasons = [];

    if (data.security?.vpn || data.security?.proxy || data.security?.tor) {
      proxyScore += 70;
      reasons.push("API reports VPN/Proxy/TOR usage.");
    }

    const asn = (data.connection?.asn_name || "").toLowerCase();
    const proxyHosts = ["croxy", "vpn", "proxy", "digitalocean", "cloudflare", "amazon", "google"];
    if (proxyHosts.some(k => asn.includes(k))) {
      proxyScore += 30;
      reasons.push("ASN belongs to known proxy/hosting provider: " + data.connection.asn_name);
    }

    const proxyDetected = proxyScore >= 50;

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        country: data.country,
        asn: data.connection?.asn_name,
        proxyDetected,
        proxyScore,
        reasons
      }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message }),
    };
  }
}
