import { Module } from '@nestjs/common';
import { AccessLoggerService } from './access-logger.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AccessLogger } from './access-logger.entity';

@Module({
  imports: [TypeOrmModule.forFeature([AccessLogger])],
  providers: [AccessLoggerService],
  exports: [AccessLoggerService]
})
export class AccessLoggerModule { }
