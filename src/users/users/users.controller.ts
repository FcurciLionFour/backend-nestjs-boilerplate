import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { Request } from 'express';
import { UsersService } from './users.service';
import { UserResponseDto } from './dto/user-response.dto';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';

@Controller('users')
@UseGuards(PermissionsGuard)
export class UsersController {
  constructor(private usersService: UsersService) {}

  // 📖 LISTAR USUARIOS
  @RequirePermissions('users.read')
  @Get()
  findAll(): Promise<UserResponseDto[]> {
    return this.usersService.findAll();
  }

  // 👤 PERFIL PROPIO
  @RequirePermissions('users.read')
  @Get('me')
  me(@Req() req: Request) {
    return req.user;
  }

  // 🔍 OBTENER USUARIO
  @RequirePermissions('users.read')
  @Get(':id')
  findOne(
    @Param('id') id: string,
    @Req() req: Request,
  ): Promise<UserResponseDto | null> {
    return this.usersService.findById(id, req.user!.sub);
  }

  // ➕ CREAR USUARIO
  @RequirePermissions('users.write')
  @Post()
  create(@Body() body: any) {
    return this.usersService.create(body);
  }

  // ✏️ ACTUALIZAR USUARIO
  @RequirePermissions('users.write')
  @Patch(':id')
  update(@Param('id') id: string, @Body() body: any, @Req() req: Request) {
    return this.usersService.update(id, body, req.user!.sub);
  }

  // 🗑️ BORRAR / DESACTIVAR USUARIO
  @RequirePermissions('users.write')
  @Delete(':id')
  remove(@Param('id') id: string, @Req() req: Request) {
    return this.usersService.remove(id, req.user!.sub);
  }
}
