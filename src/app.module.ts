import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UtilityModule } from './utility/utility.module';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [UtilityModule, PrismaModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
