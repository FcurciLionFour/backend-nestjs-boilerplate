import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  /* ---------------- REGISTER / LOGIN ---------------- */

  async register(email: string, password: string, meta?: SessionMeta) {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: { email, password: hashedPassword },
    });

    return this.createSession(user.id, meta);
  }

  async login(email: string, password: string, meta?: SessionMeta) {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user || !user.isActive) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return this.createSession(user.id, meta);
  }

  /* ---------------- REFRESH ---------------- */

  async refresh(refreshToken: string, meta?: SessionMeta) {
    let payload: any;

    try {
      payload = this.jwt.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });
    } catch {
      throw new UnauthorizedException();
    }

    const session = await this.prisma.authSession.findUnique({
      where: { id: payload.sid },
    });

    if (!session || session.revokedAt || session.expiresAt < new Date()) {
      throw new UnauthorizedException();
    }

    const valid = await bcrypt.compare(
      refreshToken,
      session.hashedRefreshToken,
    );

    // 🔥 reuse detection
    if (!valid) {
      await this.prisma.authSession.updateMany({
        where: { userId: session.userId },
        data: { revokedAt: new Date() },
      });

      throw new ForbiddenException('Refresh token reuse detected');
    }

    // rotación
    await this.prisma.authSession.update({
      where: { id: session.id },
      data: { revokedAt: new Date(), lastUsedAt: new Date() },
    });

    return this.createSession(session.userId, meta, session.id);
  }

  /* ---------------- LOGOUT ---------------- */

  async logout(sessionId: string) {
    await this.prisma.authSession.update({
      where: { id: sessionId },
      data: { revokedAt: new Date() },
    });
  }

  async logoutAll(userId: string) {
    await this.prisma.authSession.updateMany({
      where: { userId },
      data: { revokedAt: new Date() },
    });
  }

  /* ---------------- CORE ---------------- */

  private async createSession(
    userId: string,
    meta?: SessionMeta,
    replacedById?: string,
  ) {
    const sessionId = randomUUID();

    const payload = {
      sub: userId,
      sid: sessionId,
    };

    const accessToken = this.jwt.sign(payload);

    const refreshToken = this.jwt.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.prisma.authSession.create({
      data: {
        id: sessionId,
        userId,
        hashedRefreshToken,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        ip: meta?.ip,
        userAgent: meta?.userAgent,
        replacedById,
      },
    });

    return { accessToken, refreshToken };
  }
}

/* -------- TYPES -------- */

interface SessionMeta {
  ip?: string;
  userAgent?: string;
}
