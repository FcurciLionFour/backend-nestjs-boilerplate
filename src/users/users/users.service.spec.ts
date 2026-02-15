import { ForbiddenException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from 'src/prisma/prisma.service';
import { UsersService } from './users.service';

type PrismaMock = {
  user: {
    findUnique: jest.Mock;
    create: jest.Mock;
  };
  role: {
    findMany: jest.Mock;
  };
};

describe('UsersService', () => {
  let service: UsersService;

  const prismaMock: PrismaMock = {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
    },
    role: {
      findMany: jest.fn(),
    },
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
  });

  it('hashes password when creating admin-managed users', async () => {
    prismaMock.user.findUnique.mockResolvedValue(null);
    prismaMock.role.findMany.mockResolvedValue([
      { id: 'role-1', name: 'ADMIN' },
    ]);
    prismaMock.user.create.mockResolvedValue({
      id: 'user-1',
      email: 'admin-created@test.com',
      roles: [{ role: { name: 'ADMIN' } }],
    });

    const result = await service.create({
      email: 'admin-created@test.com',
      password: 'PlainTextPass123',
      roles: ['ADMIN'],
    });

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    const createCallArg = prismaMock.user.create.mock.calls[0]?.[0] as {
      data: { password: string };
    };

    expect(createCallArg.data.password).toMatch(/^\$2[aby]\$/);
    expect(result.email).toBe('admin-created@test.com');
  });

  it('throws when one or more roles are invalid', async () => {
    prismaMock.user.findUnique.mockResolvedValue(null);
    prismaMock.role.findMany.mockResolvedValue([
      { id: 'role-1', name: 'ADMIN' },
    ]);

    await expect(
      service.create({
        email: 'invalid-roles@test.com',
        password: 'abc',
        roles: ['ADMIN', 'UNKNOWN'],
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });
});
