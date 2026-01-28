import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import type { Request } from 'express';
import { UserResponseDto } from './dto/user-response.dto';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  // 🔒 protegida automáticamente por JwtGlobalGuard
  @Get()
  @UseGuards(PermissionsGuard)
  findAll(): Promise<UserResponseDto[]> {
    return this.usersService.findAll();
  }

  // 🔒 ejemplo de user autenticado
  @Get('me')
  me(@Req() req: Request) {
    return req.user;
  }

  @Get(':id')
  @UseGuards(PermissionsGuard)
  findOne(@Param('id') id: string): Promise<UserResponseDto | null> {
    return this.usersService.findById(id) as Promise<UserResponseDto | null>;
  }
}
