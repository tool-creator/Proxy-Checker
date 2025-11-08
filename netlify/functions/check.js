export async function handler(event, context) {
  const headers = event.headers;
  const ip =
    headers["x-nf-client-connection-ip"] ||
    headers["x-forwarded-for"]?.split(",")[0] ||
    headers["client-ip"] ||
    headers["cf-connecting-ip"] ||
    "8.8.8.8"; // fallback for local testing

  try {
    // --- 1️⃣ Call ipwho.is ---
    const ipwhoPromise = fetch(`https://ipwho.is/${ip}`).then((r) => r.json());

    // --- 2️⃣ Call IPHub ---
    const iphubPromise = fetch(`https://v2.api.iphub.info/ip/${ip}`, {
      headers: {
        Authorization:
          "MzAyMzk6TGFWTWhmTzRiZ3lKV1FPSHJjMWZXOEhqRHlpTmxrcGs=",
      },
    }).then((r) => r.json());

    const [ipwhoResult, iphubResult] = await Promise.allSettled([
      ipwhoPromise,
      iphubPromise,
    ]);

    const dataWho = ipwhoResult.value || {};
    const dataHub = iphubResult.value || {};

    // --- 3️⃣ Scoring logic ---
    let proxyScore = 0;
    const reasons = [];

    // ipwho.is flags
    if (dataWho.security?.vpn || dataWho.security?.proxy || dataWho.security?.tor) {
      proxyScore += 60;
      reasons.push("ipwho.is reports VPN/Proxy/TOR usage.");
    }

    // IPHub flags
    if (dataHub.block === 1) {
      proxyScore += 80;
      reasons.push("IPHub flagged this IP as a proxy/VPN.");
    } else if (dataHub.block === 2) {
      proxyScore += 40;
      reasons.push("IPHub uncertain — possible proxy/VPN.");
    }

    // ISP / ASN detection
    const isp = dataWho.connection?.isp?.trim() || "";
    const asn = dataWho.connection?.asn_name?.trim() || "";

    const lowerISP = isp.toLowerCase();
    const lowerASN = asn.toLowerCase();

    const hostingKeywords = [
      "digitalocean",
      "amazon",
      "google",
      "cloudflare",
      "ovh",
      "leaseweb",
      "hetzner",
      "linode",
      "vultr",
      "m247",
      "choopa",
      "contabo",
      "nexeon",
      "tencent",
      "azure",
      "oracle",
    ];

    // --- 4️⃣ Hard flag if exactly "Psychz Networks" ---
    if (isp.toLowerCase() === "psychz networks") {
      proxyScore = 100;
      reasons.push("ISP is exactly 'Psychz Networks' — known proxy host.");
    }

    // --- 5️⃣ Generic hosting detection ---
    else if (hostingKeywords.some((k) => lowerISP.includes(k) || lowerASN.includes(k))) {
      proxyScore += 40;
      reasons.push(
        `ISP/ASN belongs to known hosting provider: ${asn || isp}`
      );
    }

    const proxyDetected = proxyScore >= 50;

    // --- 6️⃣ Return response ---
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        {
          ip,
          country: dataWho.country,
          isp,
          asn,
          iphubBlock: dataHub.block,
          proxyDetected,
          proxyScore,
          reasons,
        },
        null,
        2
      ),
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: err.message }),
    };
  }
}
