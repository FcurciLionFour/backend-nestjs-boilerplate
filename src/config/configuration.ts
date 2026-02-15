// src/config/configuration.ts
export default () => ({
  nodeEnv: process.env.NODE_ENV,
  port: parseInt(process.env.PORT ?? '3000', 10),
  frontendUrl: process.env.FRONTEND_URL,
  corsOrigins: (process.env.CORS_ORIGINS ?? process.env.FRONTEND_URL ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),

  database: {
    url: process.env.DATABASE_URL,
  },
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN ?? '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '7d',
  },
  cookies: {
    sameSite: process.env.COOKIE_SAME_SITE,
    secure:
      process.env.COOKIE_SECURE === 'true' ||
      process.env.NODE_ENV === 'production',
    csrfMaxAgeMs: parseInt(process.env.COOKIE_CSRF_MAX_AGE_MS ?? '7200000', 10),
    refreshMaxAgeMs: parseInt(
      process.env.COOKIE_REFRESH_MAX_AGE_MS ?? '604800000',
      10,
    ),
  },
  http: {
    trustProxy: process.env.TRUST_PROXY === 'true',
    bodyLimit: process.env.HTTP_BODY_LIMIT ?? '1mb',
    urlencodedLimit: process.env.HTTP_URLENCODED_LIMIT ?? '1mb',
  },
  swagger: {
    enabled:
      process.env.SWAGGER_ENABLED === 'true' ||
      (process.env.SWAGGER_ENABLED !== 'false' &&
        process.env.NODE_ENV !== 'production'),
    path: process.env.SWAGGER_PATH ?? 'docs',
  },
});
