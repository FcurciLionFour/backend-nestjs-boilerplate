import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import {
  RATE_LIMIT_OPTIONS_KEY,
  type RateLimitOptions,
} from '../decorators/rate-limit.decorator';

interface CounterEntry {
  count: number;
  resetAt: number;
}

@Injectable()
export class RateLimitGuard implements CanActivate {
  private static readonly counters = new Map<string, CounterEntry>();

  static resetForTests(): void {
    RateLimitGuard.counters.clear();
  }

  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const options =
      this.reflector.getAllAndOverride<RateLimitOptions>(
        RATE_LIMIT_OPTIONS_KEY,
        [context.getHandler(), context.getClass()],
      ) ?? null;

    if (!options) {
      return true;
    }

    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    const now = Date.now();

    const route = req.originalUrl ?? req.url ?? context.getHandler().name;
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const key = `${ip}:${req.method}:${route}`;

    const existing = RateLimitGuard.counters.get(key);
    if (!existing || existing.resetAt <= now) {
      RateLimitGuard.counters.set(key, {
        count: 1,
        resetAt: now + options.windowMs,
      });
      this.setHeaders(res, options, options.limit - 1, options.windowMs);
      return true;
    }

    if (existing.count >= options.limit) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((existing.resetAt - now) / 1000),
      );
      this.setHeaders(res, options, 0, existing.resetAt - now);
      res.setHeader('Retry-After', retryAfterSeconds.toString());
      throw new HttpException(
        'Too many requests',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    existing.count += 1;
    const remaining = Math.max(0, options.limit - existing.count);
    this.setHeaders(res, options, remaining, existing.resetAt - now);
    return true;
  }

  private setHeaders(
    res: Response,
    options: RateLimitOptions,
    remaining: number,
    resetInMs: number,
  ) {
    res.setHeader('X-RateLimit-Limit', options.limit.toString());
    res.setHeader('X-RateLimit-Remaining', remaining.toString());
    res.setHeader(
      'X-RateLimit-Reset',
      Math.ceil(Date.now() / 1000 + resetInMs / 1000).toString(),
    );
  }
}
