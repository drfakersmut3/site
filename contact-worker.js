/**
 * Nudifi contact form handler — Cloudflare Worker
 *
 * Replaces Formspree entirely. Verifies the Cloudflare Turnstile token
 * itself, drops anything that trips the honeypot, and sends the message
 * via Resend. No third-party submission quota involved.
 *
 * Required secrets (set with `wrangler secret put <NAME>`):
 *   TURNSTILE_SECRET_KEY   — from the Cloudflare Turnstile dashboard (same widget you already use)
 *   RESEND_API_KEY         — from resend.com, after verifying your sending domain
 *
 * Required vars (set in wrangler.toml, not secret — just config):
 *   TO_EMAIL                — where you want to receive submissions
 *   FROM_EMAIL               — must be on a domain verified in Resend, e.g. contact@nudify-her.com
 *   REDIRECT_URL             — where to send the visitor after a successful submit
 */

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    let form;
    try {
      form = await request.formData();
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    // --- Honeypot: bots tend to fill every field they find ---
    // This field is visually hidden off-screen in the HTML, not display:none,
    // which catches bots that specifically skip display:none fields.
    const honeypot = (form.get("website") || "").toString().trim();
    if (honeypot !== "") {
      // Pretend it worked. Never tell the bot it was caught.
      return Response.redirect(env.REDIRECT_URL, 303);
    }

    // --- Fill-time trap: real humans take at least a couple seconds to
    // read the form and type. Scripted submissions (and many outreach
    // tools) fire almost instantly after page load. ---
    const loadedAt = parseInt(form.get("ts") || "0", 10);
    if (loadedAt && Date.now() - loadedAt < 2500) {
      return Response.redirect(env.REDIRECT_URL, 303);
    }

    // --- Turnstile verification ---
    const token = form.get("cf-turnstile-response");
    if (!token) {
      return new Response("Captcha verification missing", { status: 400 });
    }

    const verify = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET_KEY,
          response: token.toString(),
          remoteip: request.headers.get("CF-Connecting-IP") || "",
        }),
      }
    );
    const verifyResult = await verify.json();

    if (!verifyResult.success) {
      return new Response("Captcha verification failed", { status: 403 });
    }

    // --- Pull the real fields ---
    const name = (form.get("name") || "").toString().trim();
    const email = (form.get("email") || "").toString().trim();
    const service = (form.get("service") || "").toString().trim();
    const message = (form.get("message") || "").toString().trim();

    if (!name || !email || !message) {
      return new Response("Missing required fields", { status: 400 });
    }

    // --- Content filter: classic cold-outreach / SEO-pitch spam patterns.
    // These pass Turnstile fine since they're often sent from a real browser,
    // so this catches what the captcha can't. ---
    const linkCount = (message.match(/https?:\/\/|www\./gi) || []).length;
    const spamPhrases = [
      "seo", "backlink", "guest post", "link building", "increase your traffic",
      "google ranking", "social media marketing", "digital marketing agency",
      "web design services", "outsource", "cryptocurrency", "investment opportunity",
      "unsubscribe", "no longer wish to receive",
    ];
    const lowerMsg = message.toLowerCase();
    const phraseHit = spamPhrases.some((p) => lowerMsg.includes(p));

    if (linkCount >= 2 || phraseHit) {
      // Silently accept without sending — keeps the visitor experience
      // identical so a misfire doesn't look broken to a real client.
      return Response.redirect(env.REDIRECT_URL, 303);
    }

    // --- Identity heuristics: catches auto-generated bot submissions
    // where the *content* reads fine but the sender's identity doesn't
    // hold together. This is the layer that actually matters for tools
    // that pass Turnstile via real browsers / CAPTCHA-solving services. ---
    const emailParts = email.toLowerCase().split("@");
    const emailLocalPart = (emailParts[0] || "").replace(/[^a-z0-9]/g, "");
    const emailDomain = emailParts[1] || "";
    const normalizedName = name.toLowerCase().replace(/[^a-z0-9]/g, "");

    // Name is literally the email username — same random string reused
    // for both fields, a common bot-identity-generation shortcut.
    const nameMirrorsEmail =
      normalizedName.length >= 4 &&
      (normalizedName === emailLocalPart ||
        emailLocalPart.includes(normalizedName) ||
        normalizedName.includes(emailLocalPart));

    // A "word" in the name with no vowels at all (e.g. "xqfbpz") —
    // real names don't look like this regardless of language.
    const nameTokens = name.toLowerCase().split(/\s+/).filter(Boolean);
    const hasGibberishToken = nameTokens.some(
      (t) => t.length >= 5 && !/[aeiouy]/.test(t)
    );

    // Note: deliberately NOT blocking disposable/burner email domains here.
    // Given the nature of this business, privacy-conscious real clients
    // using a temp address is expected, not a spam signal — the MX check
    // below still catches fully fake/nonexistent domains either way.

    if (nameMirrorsEmail || hasGibberishToken) {
      return Response.redirect(env.REDIRECT_URL, 303);
    }

    // Live MX check — does the email's domain actually accept mail at all?
    // Catches fake/nonexistent domains common in bot identity pools.
    // Fails open (doesn't block) if the DNS lookup itself errors out, so
    // a Cloudflare DNS hiccup never costs you a real lead.
    try {
      const mxLookup = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(emailDomain)}&type=MX`,
        { headers: { Accept: "application/dns-json" } }
      );
      const mxData = await mxLookup.json();
      if (!mxData.Answer || mxData.Answer.length === 0) {
        return Response.redirect(env.REDIRECT_URL, 303);
      }
    } catch {
      // DNS check itself failed — don't penalize the visitor for that.
    }

    // --- Send via Resend ---
    const emailRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.FROM_EMAIL,
        to: [env.TO_EMAIL],
        reply_to: email,
        subject: `New project request from ${name}`,
        text:
          `Name: ${name}\n` +
          `Email: ${email}\n` +
          `Service: ${service || "Not specified"}\n\n` +
          `${message}`,
      }),
    });

    if (!emailRes.ok) {
      const errText = await emailRes.text();
      console.error("Resend error:", errText);
      return new Response("Failed to send. Please try again.", {
        status: 502,
      });
    }

    return Response.redirect(env.REDIRECT_URL, 303);
  },
};
