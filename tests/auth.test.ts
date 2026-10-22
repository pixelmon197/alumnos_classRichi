import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import type { Express } from "express";
import { authenticate, buildTestApp } from "./helpers";

describe("Autenticación", () => {
  let app: Express;

  beforeEach(() => {
    app = buildTestApp();
  });

  it("registra un usuario nuevo (201)", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ email: "ana@test.com", password: "secret123" });
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ email: "ana@test.com" });
    expect(res.body.user.id).toBeTypeOf("number");
  });

  it("rechaza correo inválido o contraseña corta (400)", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ email: "no-es-correo", password: "123" });
    expect(res.status).toBe(400);
    expect(res.body.details).toBeInstanceOf(Array);
  });

  it("rechaza registro duplicado (409)", async () => {
    await request(app)
      .post("/api/auth/register")
      .send({ email: "dup@test.com", password: "secret123" });
    const res = await request(app)
      .post("/api/auth/register")
      .send({ email: "dup@test.com", password: "secret123" });
    expect(res.status).toBe(409);
  });

  it("inicia sesión y devuelve un token (200)", async () => {
    await request(app)
      .post("/api/auth/register")
      .send({ email: "log@test.com", password: "secret123" });
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "log@test.com", password: "secret123" });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTypeOf("string");
  });

  it("rechaza credenciales incorrectas (401)", async () => {
    await request(app)
      .post("/api/auth/register")
      .send({ email: "bad@test.com", password: "secret123" });
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "bad@test.com", password: "wrongpass" });
    expect(res.status).toBe(401);
  });

  it("invalida el token tras logout (401 en peticiones posteriores)", async () => {
    await request(app)
      .post("/api/auth/register")
      .send({ email: "out@test.com", password: "secret123" });
    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "out@test.com", password: "secret123" });
    const token = login.body.token as string;

    const logout = await request(app)
      .post("/api/auth/logout")
      .set("Authorization", `Bearer ${token}`);
    expect(logout.status).toBe(200);

    const after = await request(app)
      .get("/api/students")
      .set("Authorization", `Bearer ${token}`);
    expect(after.status).toBe(401);
  });
  it("GET /api/auth/me devuelve la identidad desde los claims del JWT (200)", async () => {
    const token = await authenticate(app, "me@test.com");
    const res = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ email: "me@test.com", kind: "user" });
    expect(res.body.claims.sub).toBeTypeOf("string");
    expect(res.body.claims.jti).toBeTypeOf("string");
    expect(res.body.claims.exp).toBeGreaterThan(res.body.claims.iat);
  });

  it("GET /api/auth/me sin token o tras logout responde 401", async () => {
    const sinToken = await request(app).get("/api/auth/me");
    expect(sinToken.status).toBe(401);

    const token = await authenticate(app, "me2@test.com");
    await request(app)
      .post("/api/auth/logout")
      .set("Authorization", `Bearer ${token}`);
    const after = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${token}`);
    expect(after.status).toBe(401);
  });

  describe("POST /api/auth/refresh", () => {
    async function loginTokens(email: string) {
      await request(app)
        .post("/api/auth/register")
        .send({ email, password: "secret123" });
      const res = await request(app)
        .post("/api/auth/login")
        .send({ email, password: "secret123" });
      return res.body as { accessToken: string; refreshToken: string };
    }

    it("login devuelve accessToken y refreshToken", async () => {
      const t = await loginTokens("r1@test.com");
      expect(t.accessToken).toBeTypeOf("string");
      expect(t.refreshToken).toBeTypeOf("string");
    });

    it("intercambia el refresh token por un nuevo par (200)", async () => {
      const t = await loginTokens("r2@test.com");
      const res = await request(app)
        .post("/api/auth/refresh")
        .send({ refreshToken: t.refreshToken });
      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeTypeOf("string");
      expect(res.body.refreshToken).not.toBe(t.refreshToken);

      const me = await request(app)
        .get("/api/auth/me")
        .set("Authorization", `Bearer ${res.body.accessToken}`);
      expect(me.status).toBe(200);
    });

    it("rota el refresh token: reutilizarlo responde 401", async () => {
      const t = await loginTokens("r3@test.com");
      await request(app)
        .post("/api/auth/refresh")
        .send({ refreshToken: t.refreshToken });
      const again = await request(app)
        .post("/api/auth/refresh")
        .send({ refreshToken: t.refreshToken });
      expect(again.status).toBe(401);
    });

    it("rechaza un refresh token inválido o un access token (401)", async () => {
      const t = await loginTokens("r4@test.com");
      const bad = await request(app)
        .post("/api/auth/refresh")
        .send({ refreshToken: "basura" });
      expect(bad.status).toBe(401);
      const withAccess = await request(app)
        .post("/api/auth/refresh")
        .send({ refreshToken: t.accessToken });
      expect(withAccess.status).toBe(401);
    });

    it("responde 400 si falta refreshToken", async () => {
      const res = await request(app).post("/api/auth/refresh").send({});
      expect(res.status).toBe(400);
    });

    it("un refresh token no sirve como access token (401)", async () => {
      const t = await loginTokens("r5@test.com");
      const res = await request(app)
        .get("/api/auth/me")
        .set("Authorization", `Bearer ${t.refreshToken}`);
      expect(res.status).toBe(401);
    });
  });
});
