import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com')
);

export default {
  async fetch(request, env, ctx) {
    // CORS Headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }

    try {
      // 1. Authorization Header Check
      const authHeader = request.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response(JSON.stringify({ error: 'Unauthorized: Missing token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      const token = authHeader.split(' ')[1];

      // 2. JWT Verification using `jose`
      const expectedIssuer = `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`;
      const { payload } = await jwtVerify(token, JWKS, {
        issuer: expectedIssuer,
        audience: env.FIREBASE_PROJECT_ID,
      });

      const authenticatedUid = payload.sub;

      // 3. Parse Request Body (Size limit & content type check)
      const contentLength = request.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > 10240) {
        return new Response(JSON.stringify({ error: 'Request body too large' }), {
          status: 413,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      const body = await request.json();
      const { uid, amount, sendMoneyNumber, transactionId, PM, paymentNumber } = body;

      // 4. Input Validations
      if (!uid || uid !== authenticatedUid) {
        return new Response(JSON.stringify({ error: 'Forbidden: UID mismatch' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (typeof amount !== 'number' || amount <= 0 || !Number.isInteger(amount)) {
        return new Response(JSON.stringify({ error: 'Invalid amount' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (!['bkash', 'nagad'].includes(PM)) {
        return new Response(JSON.stringify({ error: 'Invalid payment method' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      const mobileRegex = /^01[0-9]{9}$/;
      if (!mobileRegex.test(sendMoneyNumber)) {
        return new Response(JSON.stringify({ error: 'Invalid mobile number' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (!transactionId || typeof transactionId !== 'string' || transactionId.trim().length === 0) {
        return new Response(JSON.stringify({ error: 'Transaction ID required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (paymentNumber !== '01727003670') {
        return new Response(JSON.stringify({ error: 'Invalid payment number' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      // 5. Construct Telegram Notification Message (Sanitized to prevent HTML injection)
      const sanitizedTrx = transactionId.replace(/[<>&]/g, '');
      const sanitizedNum = sendMoneyNumber.replace(/[<>&]/g, '');
      const sanitizedUid = uid.replace(/[<>&]/g, '');

      const telegramMessage = 
        `🚨 **NEW RESELLER ADD BALANCE REQUEST**\n\n` +
        `👤 **Reseller UID:** \`${sanitizedUid}\`\n` +
        `💳 **Payment Method:** ${PM.toUpperCase()}\n` +
        `📥 **Payment Number:** \`${paymentNumber}\`\n` +
        `📤 **Send Money From:** \`${sanitizedNum}\`\n` +
        `💰 **Amount:** ৳${amount}\n` +
        `🔖 **Transaction ID:** \`${sanitizedTrx}\`\n` +
        `📌 **Status:** PENDING\n\n` +
        `Payment request received successfully. Please verify and approve.`;

      // 6. Send to Telegram Bot API
      const telegramUrl = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
      const telegramRes = await fetch(telegramUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: env.TELEGRAM_CHAT_ID,
          text: telegramMessage,
          parse_mode: 'Markdown',
        }),
      });

      if (!telegramRes.ok) {
        throw new Error('Telegram API failed to send notification');
      }

      return new Response(JSON.stringify({ success: true, message: 'Notification sent successfully' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });

    } catch (err) {
      // Do not expose sensitive token/secret details in response
      return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
  },
};
