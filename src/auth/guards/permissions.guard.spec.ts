import {
  ForbiddenException,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from 'src/prisma/prisma.service';
import { PermissionsGuard } from './permissions.guard';

describe('PermissionsGuard', () => {
  const reflectorMock = {
    getAllAndOverride: jest.fn(),
  } as unknown as Reflector;

  const prismaMock = {
    userRole: {
      findMany: jest.fn(),
    },
  } as unknown as PrismaService;

  const buildContext = (user?: { sub: string }): ExecutionContext =>
    ({
      switchToHttp: () => ({ getRequest: () => ({ user }) }),
      getHandler: jest.fn(),
      getClass: jest.fn(),
    }) as unknown as ExecutionContext;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('allows when no roles/permissions required', async () => {
    (reflectorMock.getAllAndOverride as jest.Mock).mockReturnValue([]);
    const guard = new PermissionsGuard(reflectorMock, prismaMock);

    await expect(guard.canActivate(buildContext())).resolves.toBe(true);
  });

  it('throws unauthorized when requirements exist but no user', async () => {
    (reflectorMock.getAllAndOverride as jest.Mock)
      .mockReturnValueOnce([])
      .mockReturnValueOnce(['users.read']);
    const guard = new PermissionsGuard(reflectorMock, prismaMock);

    await expect(guard.canActivate(buildContext())).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('throws forbidden when user has no roles', async () => {
    (reflectorMock.getAllAndOverride as jest.Mock)
      .mockReturnValueOnce([])
      .mockReturnValueOnce(['users.read']);
    (prismaMock.userRole.findMany as jest.Mock).mockResolvedValue([]);

    const guard = new PermissionsGuard(reflectorMock, prismaMock);

    await expect(
      guard.canActivate(buildContext({ sub: 'user-1' })),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('throws forbidden when required role is missing', async () => {
    (reflectorMock.getAllAndOverride as jest.Mock)
      .mockReturnValueOnce(['ADMIN'])
      .mockReturnValueOnce([]);
    (prismaMock.userRole.findMany as jest.Mock).mockResolvedValue([
      { role: { name: 'USER', permissions: [] } },
    ]);

    const guard = new PermissionsGuard(reflectorMock, prismaMock);

    await expect(
      guard.canActivate(buildContext({ sub: 'user-1' })),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('allows when required role exists', async () => {
    (reflectorMock.getAllAndOverride as jest.Mock)
      .mockReturnValueOnce(['ADMIN'])
      .mockReturnValueOnce([]);
    (prismaMock.userRole.findMany as jest.Mock).mockResolvedValue([
      { role: { name: 'ADMIN', permissions: [] } },
    ]);

    const guard = new PermissionsGuard(reflectorMock, prismaMock);

    await expect(guard.canActivate(buildContext({ sub: 'admin-1' }))).resolves.toBe(
      true,
    );
  });

});
