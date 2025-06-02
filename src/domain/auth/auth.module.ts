import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';

// Module pour l'authentification
@Module({
  controllers: [AuthController],
})
export class AuthModule {}