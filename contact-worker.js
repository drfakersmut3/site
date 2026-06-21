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
