'use strict';
// Test-only shim: records calls; behaviour controlled via axios.__handler.
const calls = [];
async function request(method, url, data, config) {
  calls.push({ method, url, data, config });
  if (axios.__handler) return axios.__handler({ method, url, data, config });
  return { status: 200, data: { ok: true, result: { message_id: 1 } } };
}
const axios = {
  calls,
  __handler: null,
  get: (url, config) => request('GET', url, undefined, config),
  post: (url, data, config) => request('POST', url, data, config),
  create() { return axios; },
};
axios.default = axios;
module.exports = axios;
