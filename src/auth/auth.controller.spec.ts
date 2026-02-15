import { Test, TestingModule } from '@nestjs/testing';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';

describe('AuthController', () => {
  let controller: AuthController;

  const authServiceMock = {
    login: jest.fn(),
    logout: jest.fn(),
  };

  const configMock = {
    get: jest.fn().mockImplementation((key: string) => {
      if (key === 'cookies.sameSite') return 'lax';
      if (key === 'cookies.secure') return false;
      return undefined;
    }),
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        { provide: ConfigService, useValue: configMock },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('sets refresh cookie on login', async () => {
    authServiceMock.login.mockResolvedValue({
      accessToken: 'access',
      refreshToken: 'refresh',
    });

    const cookie = jest.fn();
    const res = { cookie } as unknown as Response;
    const req = {
      ip: '127.0.0.1',
      headers: { 'user-agent': 'jest' },
    } as unknown as Request;

    const result = await controller.login(
      { email: 'e@test.com', password: 'x' },
      req,
      res,
    );

    expect(cookie).toHaveBeenCalledWith(
      'refresh_token',
      'refresh',
      expect.objectContaining({ httpOnly: true, sameSite: 'lax' }),
    );
    expect(result.accessToken).toBe('access');
  });

  it('forwards logout with parsed refresh token', async () => {
    const clearCookie = jest.fn();
    const res = { clearCookie } as unknown as Response;
    const req = {
      cookies: { refresh_token: 'refresh-token' },
    } as unknown as Request;

    await controller.logout(req, res);

    expect(authServiceMock.logout).toHaveBeenCalledWith('refresh-token');
    expect(clearCookie).toHaveBeenCalledWith('refresh_token');
  });
});
