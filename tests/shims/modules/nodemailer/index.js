'use strict';
const sent = [];
module.exports = {
  sent,
  createTransport(opts) {
    return { opts, async sendMail(m) { sent.push(m); return { messageId: 'mock-' + sent.length }; } };
  },
};
