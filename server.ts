import 'dotenv/config';
import { createApp } from './server/app.ts';

const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';

const app = await createApp({ serveStatic: true });
app.listen(PORT, '0.0.0.0', () => {
  const mode = isProd ? 'production' : 'development';
  console.log(`SOC Triage App (${mode}) running on http://0.0.0.0:${PORT}`);
});
