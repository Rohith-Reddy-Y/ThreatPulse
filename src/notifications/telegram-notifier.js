/**
 * ThreatPulse — Telegram Bot Notification System
 * Sends push notifications via Telegram Bot API (FREE)
 * 
 * Setup:
 * 1. Open Telegram and search for @BotFather
 * 2. Send /newbot and follow instructions to create a bot
 * 3. Copy the bot token to .env TELEGRAM_BOT_TOKEN
 * 4. Start a chat with your bot and send any message
 * 5. Get your chat ID by visiting: https://api.telegram.org/bot<TOKEN>/getUpdates
 * 6. Copy the chat_id to .env TELEGRAM_CHAT_ID
 */

const axios = require('axios');

const TELEGRAM_API = 'https://api.telegram.org/bot';

/**
 * Send a message via Telegram Bot API
 */
async function sendTelegramMessage(botToken, chatId, message, parseMode = 'HTML') {
  try {
    const response = await axios.post(
      `${TELEGRAM_API}${botToken}/sendMessage`,
      {
        chat_id: chatId,
        text: message,
        parse_mode: parseMode,
        disable_web_page_preview: false
      },
      { timeout: 10000 }
    );

    return { success: true, messageId: response.data?.result?.message_id };
  } catch (error) {
    const errMsg = error.response?.data?.description || error.message;
    console.error(`[Telegram] Send failed: ${errMsg}`);
    return { success: false, error: errMsg };
  }
}

/**
 * Format severity emoji
 */
function severityEmoji(severity) {
  const map = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
  return map[severity] || '⚪';
}

/**
 * Format category emoji
 */
function categoryEmoji(category) {
  const map = {
    vulnerability: '🔓',
    malware: '☠️',
    breach: '💥',
    advisory: '📋',
    threat_intel: '🎯',
    darkweb: '🌑',
    news: '📰',
    community: '👥'
  };
  return map[category] || '📄';
}

/**
 * Build a formatted Telegram message for a single article
 */
function formatArticle(article) {
  const sev = severityEmoji(article.severity);
  const cat = categoryEmoji(article.category);
  const pocTag = article.has_poc ? ' ⚡<b>POC</b>' : '';
  const patchTag = article.is_patched === 1 ? ' ✅Patched' : article.is_patched === 0 ? ' ❌Unpatched' : '';
  const cveTag = article.cve_id ? `\n🏷 <code>${article.cve_id}</code>` : '';
  const author = article.author ? `\n✍️ ${article.author}` : '';
  const source = article.source_name ? `\n📡 ${article.source_name}` : '';

  return `${sev} <b>${escapeHtml(article.title)}</b>

${cat} ${(article.category || 'news').replace('_', ' ').toUpperCase()}${pocTag}${patchTag}${cveTag}${author}${source}

${escapeHtml((article.description || '').substring(0, 300))}${(article.description || '').length > 300 ? '...' : ''}

🔗 <a href="${article.url}">Read Full Article →</a>`;
}

/**
 * Escape HTML entities for Telegram
 */
function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Send threat alerts via Telegram
 */
async function sendTelegramAlert(articles, botToken, chatId) {
  const token = botToken || process.env.TELEGRAM_BOT_TOKEN;
  const chat = chatId || process.env.TELEGRAM_CHAT_ID;

  if (!token || !chat) {
    return { success: false, error: 'Telegram bot not configured' };
  }

  try {
    const results = [];

    // If many articles, send a summary first
    if (articles.length > 5) {
      const critCount = articles.filter(a => a.severity === 'critical').length;
      const highCount = articles.filter(a => a.severity === 'high').length;
      const pocCount = articles.filter(a => a.has_poc).length;

      const summary = `🛡️ <b>ThreatPulse Alert</b>

📊 <b>${articles.length} new threats detected</b>
${critCount > 0 ? `🔴 ${critCount} Critical\n` : ''}${highCount > 0 ? `🟠 ${highCount} High\n` : ''}${pocCount > 0 ? `⚡ ${pocCount} with POC\n` : ''}
🕐 ${new Date().toLocaleString()}

<i>Sending top threats below...</i>`;

      await sendTelegramMessage(token, chat, summary);
      await sleep(500);

      // Send only top 10 most critical
      const topArticles = articles
        .sort((a, b) => {
          const order = { critical: 4, high: 3, medium: 2, low: 1 };
          return (order[b.severity] || 0) - (order[a.severity] || 0);
        })
        .slice(0, 10);

      for (const article of topArticles) {
        const msg = formatArticle(article);
        const result = await sendTelegramMessage(token, chat, msg);
        results.push(result);
        await sleep(300); // Telegram rate limit: ~30 msg/sec
      }
    } else {
      // Send each article individually
      for (const article of articles) {
        const msg = formatArticle(article);
        const result = await sendTelegramMessage(token, chat, msg);
        results.push(result);
        await sleep(300);
      }
    }

    const successCount = results.filter(r => r.success).length;
    console.log(`[Telegram] Sent ${successCount}/${results.length} alert messages`);
    return { success: true, sent: successCount, total: results.length };

  } catch (error) {
    console.error(`[Telegram] Alert failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

/**
 * Send a test notification
 */
async function sendTestTelegram(botToken, chatId) {
  const token = botToken || process.env.TELEGRAM_BOT_TOKEN;
  const chat = chatId || process.env.TELEGRAM_CHAT_ID;

  if (!token || !chat) {
    return { success: false, error: 'Telegram bot not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env' };
  }

  const testMsg = `🧪 <b>ThreatPulse Test Notification</b>

✅ Your Telegram notifications are working correctly!

🛡️ You will receive alerts for new threats based on your severity threshold settings.

🕐 ${new Date().toLocaleString()}`;

  return sendTelegramMessage(token, chat, testMsg);
}

/**
 * Get bot info to verify token is valid
 */
async function verifyBot(botToken) {
  try {
    const token = botToken || process.env.TELEGRAM_BOT_TOKEN;
    if (!token) return { success: false, error: 'No bot token provided' };

    const response = await axios.get(`${TELEGRAM_API}${token}/getMe`, { timeout: 10000 });
    return { success: true, bot: response.data?.result };
  } catch (error) {
    return { success: false, error: error.response?.data?.description || error.message };
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { sendTelegramAlert, sendTestTelegram, verifyBot };
