module.exports = { createTransport() { return { sendMail: async () => ({ messageId: 'stub' }), verify: async () => true }; } };
