import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserResponseDto } from './dto/user-response.dto';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  // 📖 LISTAR USUARIOS (ADMIN)
  async findAll(): Promise<UserResponseDto[]> {
    const users = await this.prisma.user.findMany({
      where: {
        isActive: true,
      },
      select: {
        id: true,
        email: true,
        roles: {
          include: {
            role: true,
          },
        },
      },
    });

    return users.map((u) => ({
      id: u.id,
      email: u.email,
      roles: u.roles.map((ur) => ur.role.name),
    }));
  }

  // 🔍 OBTENER USUARIO
  async findById(
    id: string,
    requesterId: string,
  ): Promise<UserResponseDto | null> {
    await this.assertCanAccessUser(id, requesterId);
    if (id !== requesterId) {
      // acá más adelante podrías chequear si es ADMIN
      throw new ForbiddenException('Access denied');
    }
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        roles: {
          include: {
            role: true,
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      id: user.id,
      email: user.email,
      roles: user.roles.map((ur) => ur.role.name),
    };
  }

  // ➕ CREAR USUARIO (ADMIN)
  async create(data: { email: string; password: string }) {
    const exists = await this.prisma.user.findUnique({
      where: { email: data.email },
    });

    if (exists) {
      throw new ForbiddenException('User already exists');
    }

    const user = await this.prisma.user.create({
      data: {
        email: data.email,
        password: data.password, // ⚠️ luego lo hasheás (AuthService)
        isActive: true,
      },
    });

    return {
      id: user.id,
      email: user.email,
    };
  }

  // ✏️ ACTUALIZAR USUARIO
  async update(
    id: string,
    data: Partial<{ email: string; isActive: boolean }>,
    requesterId: string,
  ) {
    await this.assertCanAccessUser(id, requesterId);
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updated = await this.prisma.user.update({
      where: { id },
      data,
    });

    return {
      id: updated.id,
      email: updated.email,
      isActive: updated.isActive,
    };
  }

  // 🗑️ BORRAR USUARIO (soft delete)
  async remove(id: string, requesterId: string) {
    await this.assertCanAccessUser(id, requesterId);
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    await this.prisma.user.update({
      where: { id },
      data: {
        isActive: false,
      },
    });

    return { success: true };
  }
  private async assertCanAccessUser(
    targetUserId: string,
    requesterUserId: string,
  ): Promise<void> {
    console.log('targetUserId:', targetUserId);
    console.log('requesterUserId:', requesterUserId);
    if (targetUserId === requesterUserId) {
      return;
    }

    const isAdmin = await this.prisma.userRole.findFirst({
      where: {
        userId: requesterUserId,
        role: {
          name: 'ADMIN',
        },
      },
    });

    if (!isAdmin) {
      throw new ForbiddenException('Access denied');
    }
  }
}
