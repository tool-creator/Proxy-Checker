export async function handler(event, context) {
  const headers = event.headers;
  const ip =
    headers["x-nf-client-connection-ip"] ||
    headers["x-forwarded-for"]?.split(",")[0] ||
    headers["client-ip"] ||
    headers["cf-connecting-ip"] ||
    "8.8.8.8"; // fallback for local testing

  try {
    // Fetch data from ipwho.is
    const ipwhoPromise = fetch(`https://ipwho.is/${ip}`).then((r) => r.json());

    // Fetch data from IPHub
    const iphubPromise = fetch(`https://v2.api.iphub.info/ip/${ip}`, {
      headers: { Authorization: "MzAyMzk6TGFWTWhmTzRiZ3lKV1FPSHJjMWZXOEhqRHlpTmxrcGs=" },
    }).then((r) => r.json());

    const [ipwho, iphub] = await Promise.allSettled([ipwhoPromise, iphubPromise]);

    const dataWho = ipwho.value || {};
    const dataHub = iphub.value || {};

    // Determine proxy score
    let proxyScore = 0;
    const reasons = [];

    // ipwho.is detection
    if (dataWho.security?.vpn || dataWho.security?.proxy || dataWho.security?.tor) {
      proxyScore += 60;
      reasons.push("ipwho.is reports VPN/Proxy/TOR usage.");
    }

    // iphub.info detection
    if (dataHub.block === 1) {
      proxyScore += 80;
      reasons.push("IPHub flagged this IP as a proxy/VPN.");
    } else if (dataHub.block === 2) {
      proxyScore += 40;
      reasons.push("IPHub uncertain — possible proxy/VPN.");
    }

    // ASN / hosting detection
    const asn = (dataWho.connection?.asn_name || "").toLowerCase();
    const proxyHosts = ["croxy", "vpn", "proxy", "digitalocean", "cloudflare", "amazon", "google"];
    if (proxyHosts.some((k) => asn.includes(k))) {
      proxyScore += 20;
      reasons.push("ASN belongs to known proxy/hosting provider: " + dataWho.connection.asn_name);
    }

    const proxyDetected = proxyScore >= 50;

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        country: dataWho.country,
        isp: dataWho.connection?.isp,
        asn: dataWho.connection?.asn_name,
        iphubBlock: dataHub.block,
        proxyDetected,
        proxyScore,
        reasons,
      }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message }),
    };
  }
}
