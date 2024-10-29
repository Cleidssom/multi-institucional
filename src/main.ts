import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Configuração básica do Swagger
  const config = new DocumentBuilder()
    .setTitle('API Site institucional')
    .setDescription('API para gerenciamento Pagina institucional')
    .setVersion('1.0')
    .addTag('Status')
    .addTag('Utility')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const port = 3001;
  await app.listen(port);

  // Imprimir link clicável no terminal
  console.log(`Application is running on: http://localhost:${port}/api`);
}
bootstrap();