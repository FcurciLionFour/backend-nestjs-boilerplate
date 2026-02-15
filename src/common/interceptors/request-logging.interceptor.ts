import {
  CallHandler,
  ExecutionContext,
  HttpException,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { tap } from 'rxjs/operators';

@Injectable()
export class RequestLoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(RequestLoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler) {
    if (context.getType() !== 'http') {
      return next.handle();
    }

    const startedAt = Date.now();
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    const requestId = req.requestId;
    const method = req.method;
    const path = req.originalUrl ?? req.url;
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];

    return next.handle().pipe(
      tap({
        next: () => {
          this.logger.log(
            JSON.stringify({
              event: 'http_request',
              level: 'info',
              requestId,
              method,
              path,
              statusCode: res.statusCode,
              durationMs: Date.now() - startedAt,
              ip,
              userAgent,
            }),
          );
        },
        error: (error: unknown) => {
          const statusCode =
            error instanceof HttpException ? error.getStatus() : 500;

          this.logger.error(
            JSON.stringify({
              event: 'http_request',
              level: 'error',
              requestId,
              method,
              path,
              statusCode,
              durationMs: Date.now() - startedAt,
              ip,
              userAgent,
              error:
                error instanceof Error ? error.message : 'Unhandled exception',
            }),
          );
        },
      }),
    );
  }
}
