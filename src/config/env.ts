import path from "node:path";

/**
 * Configuración de la aplicación, leída de variables de entorno con
 * valores por defecto pensados para ejecución local.
 */
export const config = {
  port: Number(process.env.PORT ?? 3000),
  jwtSecret: process.env.JWT_SECRET ?? "dev-secret-change-me",
  jwtExpiresIn: process.env.JWT_EXPIRES_IN ?? "1h",
  jwtRefreshSecret:
    process.env.JWT_REFRESH_SECRET ?? "dev-refresh-secret-change-me",
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? "7d",
  dbPath: process.env.DB_PATH ?? path.join(process.cwd(), "data", "app.db"),
  bcryptRounds: 10,
} as const;
