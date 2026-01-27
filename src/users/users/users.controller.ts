import { Controller, Get, Param, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import type { Request } from 'express';
import { UserResponseDto } from './dto/user-response.dto';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  // 🔒 protegida automáticamente por JwtGlobalGuard
  @Get()
  findAll(): Promise<UserResponseDto[]> {
    return this.usersService.findAll() as Promise<UserResponseDto[]>;
  }

  // 🔒 ejemplo de user autenticado
  @Get('me')
  me(@Req() req: Request) {
    return req.user;
  }

  @Get(':id')
  findOne(@Param('id') id: string): Promise<UserResponseDto | null> {
    return this.usersService.findById(id) as Promise<UserResponseDto | null>;
  }
}
