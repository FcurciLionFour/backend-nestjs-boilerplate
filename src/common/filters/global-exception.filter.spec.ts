import {
  ArgumentsHost,
  BadRequestException,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { GlobalExceptionFilter } from './global-exception.filter';

function createHost({ requestId, path }: { requestId?: string; path: string }) {
  const response = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  };
  const request = {
    requestId,
    url: path,
    originalUrl: path,
  };

  return {
    response,
    host: {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => response,
      }),
    },
  };
}

describe('GlobalExceptionFilter', () => {
  const filter = new GlobalExceptionFilter();

  it('maps unauthorized exception to standard payload', () => {
    const { host, response } = createHost({
      requestId: 'req-1',
      path: '/secure',
    });

    filter.catch(
      new UnauthorizedException('Invalid token'),
      host as unknown as ArgumentsHost,
    );

    expect(response.status).toHaveBeenCalledWith(401);
    expect(response.json).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 401,
        code: 'UNAUTHORIZED',
        message: 'Invalid token',
        path: '/secure',
        requestId: 'req-1',
      }),
    );
  });

  it('includes validation errors array on bad request', () => {
    const { host, response } = createHost({
      requestId: 'req-2',
      path: '/auth/register',
    });

    filter.catch(
      new BadRequestException(['email must be an email', 'password too short']),
      host as unknown as ArgumentsHost,
    );

    expect(response.status).toHaveBeenCalledWith(400);
    expect(response.json).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 400,
        code: 'BAD_REQUEST',
        message: 'email must be an email',
        errors: ['email must be an email', 'password too short'],
      }),
    );
  });

  it('maps forbidden exception to FORBIDDEN', () => {
    const { host, response } = createHost({
      requestId: undefined,
      path: '/rbac/users-read',
    });

    filter.catch(
      new ForbiddenException('Not enough permissions'),
      host as unknown as ArgumentsHost,
    );

    expect(response.status).toHaveBeenCalledWith(403);
    expect(response.json).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 403,
        code: 'FORBIDDEN',
        message: 'Not enough permissions',
      }),
    );
  });
});
