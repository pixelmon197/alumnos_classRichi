import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { config } from "../config/env";
import { conflict, unauthorized } from "../errors/httpError";
import { toPublicStudent } from "../repositories/studentRepository";
import type { PublicStudent } from "../repositories/studentRepository";
import type { UserRepository } from "../repositories/userRepository";
import type { TokenRepository } from "../repositories/tokenRepository";
import type { StudentRepository } from "../repositories/studentRepository";

export interface PublicUser {
  id: number;
  email: string;
}

export type CurrentUser =
  | ({ kind: "user" } & PublicUser)
  | ({ kind: "student" } & PublicStudent);

export interface TokenPayload {
  sub: string;
  email: string;
  kind: "user" | "student";
  /** Tipo de token: los refresh tokens no sirven para acceder a recursos. */
  typ?: "access" | "refresh";
  jti: string;
  exp: number;
  iat: number;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export class AuthService {
  constructor(
    private readonly users: UserRepository,
    private readonly tokens: TokenRepository,
    private readonly students: StudentRepository,
  ) {}

  async register(email: string, password: string): Promise<PublicUser> {
    if (this.users.findByEmail(email)) {
      throw conflict("Ya existe un usuario con ese correo electrónico");
    }
    const hash = await bcrypt.hash(password, config.bcryptRounds);
    const user = this.users.create(email, hash);
    return { id: user.id, email: user.email };
  }

  async login(
    email: string,
    password: string,
  ): Promise<{
    token: string;
    accessToken: string;
    refreshToken: string;
    user: PublicUser;
  }> {
    // Se puede iniciar sesión con una cuenta de usuario (registro) o con
    // las credenciales de un estudiante (email + password).
    const user = this.users.findByEmail(email);
    const student = user ? undefined : this.students.findByEmail(email);
    const account = user
      ? { id: user.id, email: user.email, hash: user.password_hash, kind: "user" }
      : student
        ? {
            id: student.id,
            email: student.email,
            hash: student.password_hash,
            kind: "student",
          }
        : undefined;

    if (!account || account.hash === "") {
      throw unauthorized("Credenciales inválidas");
    }

    const ok = await bcrypt.compare(password, account.hash);
    if (!ok) throw unauthorized("Credenciales inválidas");

    const pair = this.issueTokens(account.id, account.email, account.kind as "user" | "student");
    // `token` se conserva por compatibilidad (es el mismo access token).
    return { token: pair.accessToken, ...pair, user: { id: account.id, email: account.email } };
  }

  /** Firma un access token y un refresh token nuevos para la cuenta. */
  private issueTokens(
    id: number,
    email: string,
    kind: "user" | "student",
  ): TokenPair {
    const claims = { sub: String(id), email, kind };
    const accessToken = jwt.sign(
      { ...claims, typ: "access" },
      config.jwtSecret,
      {
        expiresIn: config.jwtExpiresIn as SignOptions["expiresIn"],
        jwtid: randomUUID(),
      },
    );
    const refreshToken = jwt.sign(
      { ...claims, typ: "refresh" },
      config.jwtRefreshSecret,
      {
        expiresIn: config.jwtRefreshExpiresIn as SignOptions["expiresIn"],
        jwtid: randomUUID(),
      },
    );
    return { accessToken, refreshToken };
  }

  /**
   * Intercambia un refresh token válido por un nuevo par de tokens.
   * Aplica rotación: el refresh token usado se revoca, así que no puede
   * reutilizarse.
   */
  refresh(refreshToken: string): TokenPair {
    let decoded: TokenPayload;
    try {
      decoded = jwt.verify(refreshToken, config.jwtRefreshSecret) as TokenPayload;
    } catch {
      throw unauthorized("Refresh token inválido o expirado");
    }
    if (decoded.typ !== "refresh" || !decoded.jti) {
      throw unauthorized("Refresh token inválido o expirado");
    }
    if (this.tokens.isRevoked(decoded.jti)) {
      throw unauthorized("Refresh token inválido o expirado");
    }

    // La cuenta debe seguir existiendo.
    const id = Number(decoded.sub);
    const exists =
      decoded.kind === "student"
        ? this.students.findById(id)
        : this.users.findById(id);
    if (!exists) throw unauthorized("El usuario ya no existe");

    this.tokens.revoke(decoded.jti, decoded.exp);
    return this.issueTokens(id, decoded.email, decoded.kind);
  }

  /**
   * Devuelve los datos actuales del usuario autenticado consultando la base
   * de datos por su id (no se usan los datos que viajan dentro del token).
   */
  getCurrentUser(payload: TokenPayload): CurrentUser {
    const id = Number(payload.sub);
    if (payload.kind === "student") {
      const student = this.students.findById(id);
      if (!student) throw unauthorized("El usuario ya no existe");
      return { kind: "student", ...toPublicStudent(student) };
    }
    const user = this.users.findById(id);
    if (!user) throw unauthorized("El usuario ya no existe");
    return { kind: "user", id: user.id, email: user.email };
  }

  /** Revoca el token actual (logout) usando su jti y expiración. */
  logout(payload: TokenPayload): void {
    this.tokens.revoke(payload.jti, payload.exp);
  }

  verify(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, config.jwtSecret) as TokenPayload;
      if (!decoded.jti) throw new Error("token sin jti");
      if (decoded.typ === "refresh") throw new Error("refresh token no permitido");
      if (this.tokens.isRevoked(decoded.jti)) {
        throw unauthorized("La sesión ha sido cerrada");
      }
      return decoded;
    } catch (err) {
      if (err instanceof Error && err.name === "HttpError") throw err;
      throw unauthorized("Token inválido o expirado");
    }
  }
}
