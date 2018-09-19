const proxyMiddleware = require('http-proxy-middleware');
const fallbackMiddleware = require('connect-history-api-fallback');

module.exports = {
  port: 8080,
  server: {
    middleware: {
      1: proxyMiddleware('/saml', {
        target: 'http://localhost:8094',
        changeOrigin: true
      }),
      2: proxyMiddleware('/user', {
        target: 'http://localhost:8094',
        changeOrigin: true
      }),
      3: proxyMiddleware('/admin', {
        target: 'http://localhost:8094',
        changeOrigin: true
      }),
      4: fallbackMiddleware({
        index: '/index.html', verbose: true
      })
    }
  }
};
