import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import type { Request } from 'express';

@Injectable()
export class CsrfGuard implements CanActivate {
  private readonly logger = new Logger(CsrfGuard.name);

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();

    const method = req.method.toUpperCase();

    const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    if (!isMutating) {
      return true;
    }

    const csrfCookie = req.cookies?.['csrf_token'];
    const csrfHeader = req.headers['x-csrf-token'];

    if (!csrfCookie || !csrfHeader) {
      this.logger.warn(
        JSON.stringify({
          event: 'csrf.missing',
          method,
          path: req.originalUrl ?? req.url,
        }),
      );
      throw new ForbiddenException('CSRF token missing');
    }

    const headerValue =
      typeof csrfHeader === 'string'
        ? csrfHeader
        : Array.isArray(csrfHeader)
          ? csrfHeader[0]
          : undefined;

    if (!headerValue || csrfCookie !== headerValue) {
      this.logger.warn(
        JSON.stringify({
          event: 'csrf.invalid',
          method,
          path: req.originalUrl ?? req.url,
        }),
      );
      throw new ForbiddenException('Invalid CSRF token');
    }

    return true;
  }
}
