import { createServer } from 'node:http';
import { hostname } from 'node:os';

const runId = process.env.KOI_FIXTURE_RUN_ID;
if (!runId) throw new Error('KOI_FIXTURE_RUN_ID is required');

const server = createServer((request, response) => {
  const body = JSON.stringify({
    fixture: 'koi-operator-preview',
    run_id: runId,
    container_hostname: hostname(),
    request_path: request.url,
  });
  response.writeHead(200, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
  });
  response.end(body);
});

server.listen(8080, '0.0.0.0');

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
