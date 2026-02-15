import {
  Controller,
  Post,
  Body,
  Req,
  Res,
  UseGuards,
  Get,
} from '@nestjs/common';

import type { Request, Response, CookieOptions } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { Public } from './decorators/public.decorator';
import { RegisterDto } from './dto/register.dto';
import { randomUUID } from 'crypto';
import { CsrfGuard } from './guards/csrf.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { ConfigService } from '@nestjs/config';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {}

  private getCookieOptions(httpOnly: boolean): CookieOptions {
    const sameSite =
      this.config.get<'lax' | 'strict' | 'none'>('cookies.sameSite') ?? 'lax';
    const secure = this.config.get<boolean>('cookies.secure') ?? false;

    return {
      httpOnly,
      sameSite,
      secure,
      path: '/',
    };
  }

  @Public()
  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto.email, dto.password);
  }

  @Public()
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.login(dto.email, dto.password, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.cookie(
      'refresh_token',
      tokens.refreshToken,
      this.getCookieOptions(true),
    );

    return { accessToken: tokens.accessToken };
  }

  @Get('me')
  me(@CurrentUser() user: { sub: string }) {
    return this.authService.getSession(user.sub);
  }

  @UseGuards(CsrfGuard)
  @Public()
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken =
      typeof req.cookies?.refresh_token === 'string'
        ? req.cookies.refresh_token
        : '';

    const tokens = await this.authService.refresh(refreshToken, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.cookie(
      'refresh_token',
      tokens.refreshToken,
      this.getCookieOptions(true),
    );

    return { accessToken: tokens.accessToken };
  }

  @UseGuards(CsrfGuard)
  @Post('logout')
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken =
      typeof req.cookies?.refresh_token === 'string'
        ? req.cookies.refresh_token
        : '';

    res.clearCookie('refresh_token');

    return this.authService.logout(refreshToken);
  }

  @Public()
  @Get('csrf')
  getCsrf(@Res({ passthrough: true }) res: Response) {
    const csrfToken = randomUUID();

    res.cookie('csrf_token', csrfToken, this.getCookieOptions(false));

    return { ok: true };
  }

  @Public()
  @Post('forgot-password')
  forgotPassword(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  @Public()
  @Post('reset-password')
  resetPassword(
    @Body('token') token: string,
    @Body('newPassword') newPassword: string,
  ) {
    return this.authService.resetPassword(token, newPassword);
  }

  @Post('change-password')
  changePassword(
    @CurrentUser() user: { sub: string },
    @Body('currentPassword') currentPassword: string,
    @Body('newPassword') newPassword: string,
  ) {
    return this.authService.changePassword(
      user.sub,
      currentPassword,
      newPassword,
    );
  }
}
