import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ControlCenterServer } from './server.js';
import { ProcessManager } from './process-manager.js';

export function startControlCenter(port = null, options = {}) {
  const finalPort = port || Number(process.env.CONTROL_CENTER_PORT || 8090);
  const processManager = options.processManager || new ProcessManager();
  const server = new ControlCenterServer({ processManager });
  const rawServer = server.createServer();

  return new Promise(resolve => {
    // SECURITY: the supervisor can start/stop every service and has no login of its own,
    // so it only listens on loopback. The authenticated merchant admin panel proxies to it.
    const host = process.env.CONTROL_CENTER_HOST || '127.0.0.1';
    const instance = rawServer.listen(finalPort, host, () => {
      console.log(`[Control Center] Supervisor listening on http://localhost:${finalPort}`);
      resolve({
        server,
        processManager,
        port: finalPort,
        close: async () => {
          await processManager.stopAll();
          return new Promise(cb => instance.close(cb));
        }
      });
    });
  });
}

// Auto-run if executed directly as main script
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startControlCenter();
}
