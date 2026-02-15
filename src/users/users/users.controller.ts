import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { UserResponseDto } from './dto/user-response.dto';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { JwtGlobalGuard } from 'src/auth/guards/jwt-global.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';

interface CreateUserBody {
  email: string;
  password: string;
  roles: string[];
}

interface UpdateUserBody {
  email?: string;
  isActive?: boolean;
  roles?: string[];
}

interface CreateUserBody {
  email: string;
  password: string;
  roles: string[];
}

interface UpdateUserBody {
  email?: string;
  isActive?: boolean;
  roles?: string[];
}

@Controller('users')
@UseGuards(JwtGlobalGuard, PermissionsGuard)
export class UsersController {
  constructor(private usersService: UsersService) {}

  @RequirePermissions('users.read')
  @Roles('ADMIN')
  @Get()
  @UseGuards(PermissionsGuard)
  findAll(): Promise<UserResponseDto[]> {
    return this.usersService.findAll();
  }

  @Get('me')
  me(@CurrentUser() user: { sub: string }) {
    return user;
  }

  @Get(':id')
  @UseGuards(PermissionsGuard)
  findOne(
    @Param('id') id: string,
    @CurrentUser() user: { sub: string },
  ): Promise<UserResponseDto | null> {
    return this.usersService.findById(id, user.sub);
  }

  @RequirePermissions('users.write')
  @Post()
  @UseGuards(PermissionsGuard)
  create(@Body() body: CreateUserBody) {
    return this.usersService.create(body);
  }

  @RequirePermissions('users.write')
  @Patch(':id')
  @UseGuards(PermissionsGuard)
  update(
    @Param('id') id: string,
    @Body() body: UpdateUserBody,
    @CurrentUser() user: { sub: string },
  ) {
    return this.usersService.update(id, body, user.sub);
  }

  @RequirePermissions('users.write')
  @Delete(':id')
  @UseGuards(PermissionsGuard)
  remove(@Param('id') id: string, @CurrentUser() user: { sub: string }) {
    return this.usersService.remove(id, user.sub);
  }
}
