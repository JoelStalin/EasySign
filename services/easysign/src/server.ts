import { buildApp } from './app.js';
const app = buildApp();
const port = Number(process.env.PORT ?? 3000);
app.listen({ port, host: '127.0.0.1' }).catch((error: unknown) => { app.log.error(error); process.exit(1); });
