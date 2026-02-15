import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const adminRole = await prisma.role.upsert({
    where: { name: 'ADMIN' },
    update: {},
    create: {
      name: 'ADMIN',
      description: 'Administrator',
    },
  });

  const userRole = await prisma.role.upsert({
    where: { name: 'USER' },
    update: {},
    create: {
      name: 'USER',
      description: 'Regular user',
    },
  });

  const usersRead = await prisma.permission.upsert({
    where: { key: 'users.read' },
    update: {},
    create: {
      key: 'users.read',
      description: 'Read users',
    },
  });

  const usersWrite = await prisma.permission.upsert({
    where: { key: 'users.write' },
    update: {},
    create: {
      key: 'users.write',
      description: 'Write users',
    },
  });

  await prisma.rolePermission.upsert({
    where: {
      roleId_permissionId: {
        roleId: adminRole.id,
        permissionId: usersRead.id,
      },
    },
    update: {},
    create: {
      roleId: adminRole.id,
      permissionId: usersRead.id,
    },
  });

  await prisma.rolePermission.upsert({
    where: {
      roleId_permissionId: {
        roleId: adminRole.id,
        permissionId: usersWrite.id,
      },
    },
    update: {},
    create: {
      roleId: adminRole.id,
      permissionId: usersWrite.id,
    },
  });

  // Keep USER role with least privilege by default.
  await prisma.rolePermission.deleteMany({
    where: {
      roleId: userRole.id,
      permissionId: usersRead.id,
    },
  });

  const seedAdminEmail = process.env.SEED_ADMIN_EMAIL;
  if (!seedAdminEmail) {
    console.log(
      'SEED_ADMIN_EMAIL not set, skipping automatic ADMIN role assignment.',
    );
    return;
  }

  const user = await prisma.user.findUnique({
    where: { email: seedAdminEmail },
  });

  if (!user) {
    console.warn(
      `SEED_ADMIN_EMAIL=${seedAdminEmail} does not exist. Skipping ADMIN role assignment.`,
    );
    return;
  }

  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId: user.id,
        roleId: adminRole.id,
      },
    },
    update: {},
    create: {
      userId: user.id,
      roleId: adminRole.id,
    },
  });

  console.log(`Assigned ADMIN role to ${seedAdminEmail}.`);
}

main()
  .catch((error: unknown) => {
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
