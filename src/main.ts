import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  app.use(cookieParser());

  app.enableCors({
    origin: config.get<string[]>('corsOrigins') ?? [],
    credentials: true,
  });

  const port = config.get<number>('port') ?? 3000;
  await app.listen(port);
}
void bootstrap();
