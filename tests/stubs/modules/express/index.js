// Test-only stand-in for express: a Router that records routes so tests can
// dispatch fake requests straight to the handlers.
'use strict';
function Router() {
  const routes = [];
  const r = { routes };
  for (const m of ['get', 'post', 'put', 'delete']) {
    r[m] = (path, ...handlers) => { routes.push({ method: m.toUpperCase(), path, handlers }); return r; };
  }
  r.use = () => r;
  return r;
}
// Minimal app that records middleware so tests can poke at server.js wiring.
function express() {
  const app = { stack: [], settings: {}, listening: false };
  app.use = (...args) => { app.stack.push({ kind: 'use', args }); return app; };
  app.get = (...args) => {
    if (args.length === 1) return app.settings[args[0]];
    app.stack.push({ kind: 'get', args }); return app;
  };
  app.set = (k, v) => { app.settings[k] = v; return app; };
  app.listen = (port, cb) => { app.listening = true; return { close() {} }; };
  express.lastApp = app;
  return app;
}
express.Router = Router;
express.json = () => (req, res, next) => next();
express.urlencoded = () => (req, res, next) => next();
express.static = () => (req, res, next) => next();
module.exports = express;
