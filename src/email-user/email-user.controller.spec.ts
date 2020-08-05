import { Test, TestingModule } from '@nestjs/testing';
import { EmailUserController } from './email-user.controller';

describe('EmailUser Controller', () => {
  let controller: EmailUserController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [EmailUserController],
    }).compile();

    controller = module.get<EmailUserController>(EmailUserController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
