/**
 * Vercel Serverless Function Entrypoint
 * Forwards requests to the VeriRespond server handler.
 */

const server = require('../src/server.js');

module.exports = server;
